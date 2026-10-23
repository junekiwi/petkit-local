"""Stitcher tests. The concat/verify tests need a real ffmpeg (they generate
actual video and check the joined result decodes) and are SKIPPED when it is
unavailable, so the suite still runs on a machine without it. Skipped, not
returned from: an early `return` is reported as a pass, which is how these
tests once passed in CI without running a single ffmpeg.

The orchestration of `stitch_episode` — which chunks are retried, kept, deleted
and marked — is also tested without ffmpeg, by standing in for the four media
primitives. Real files on disk have version-dependent ways of failing, so the
real-video tests cannot be relied on to reach a given branch."""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from petkit_local.events.store import EventStore
from petkit_local.media import stitch

HAVE_FFMPEG = shutil.which("ffmpeg") is not None and shutil.which("ffprobe") is not None

requires_ffmpeg = pytest.mark.skipif(not HAVE_FFMPEG, reason="ffmpeg/ffprobe not installed")


def _make_clip(path: str, seconds: int = 1, size: int = 64) -> None:
    """Generate a small real H.264 clip with ffmpeg's test source.

    Skips the calling test if this ffmpeg build cannot encode one (no libx264).
    """
    r = subprocess.run(
        ["ffmpeg", "-y", "-f", "lavfi", "-i",
         f"testsrc=duration={seconds}:size={size}x{size}:rate=10",
         "-c:v", "libx264", "-pix_fmt", "yuv420p", path],
        capture_output=True,
    )
    if r.returncode != 0 or not os.path.isfile(path):
        pytest.skip("this ffmpeg build cannot encode H.264 test clips")


async def _store(tmp):
    """An EventStore inside `tmp`, closed when the test's event loop tears down.

    Not the `event_store` fixture: these tests keep the database in the same
    temporary tree as the clips they stitch, and several build more than one.
    """
    store = EventStore(Path(tmp) / "petkit.db")
    _OPEN_STORES.append(store)
    return store


#: Every store `_store` handed out this test, drained by the autouse fixture
#: below. A store holds an aiosqlite pool bound to the test's own event loop.
_OPEN_STORES: list[EventStore] = []


@pytest.fixture(autouse=True)
async def _close_stores():
    yield
    while _OPEN_STORES:
        await _OPEN_STORES.pop().close()


def test_expected_duration_sums_chunk_durations():
    chunks = [{"duration_ms": 4000}, {"duration_ms": 3999}, {"duration_ms": None}]
    assert stitch._expected_duration_sec(chunks) == 7.999
    assert stitch._expected_duration_sec([{"duration_ms": None}]) is None
    assert stitch._expected_duration_sec([]) is None
    # A raw device string loses that chunk's contribution, not the whole join.
    assert stitch._expected_duration_sec([{"duration_ms": "4000ms"},
                                          {"duration_ms": 1000}]) == 1.0


@requires_ffmpeg
def test_concat_and_verify_real_video():
    with tempfile.TemporaryDirectory() as tmp:
        parts = []
        for i in range(3):
            p = os.path.join(tmp, f"part{i}.mp4")
            _make_clip(p, seconds=1)
            parts.append(p)

        out = os.path.join(tmp, "joined.mp4")
        ok = asyncio.run(stitch.concat_videos(parts, out, work_dir=os.path.join(tmp, "work")))
        assert ok is True
        assert os.path.isfile(out)
        # 3 x 1s clips -> ~3s, and every frame must decode
        assert asyncio.run(stitch.verify_video(out, expected_duration_sec=3.0)) is True


@requires_ffmpeg
def test_verify_rejects_truncated_file():
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.mp4")
        _make_clip(good, seconds=1)
        bad = os.path.join(tmp, "bad.mp4")
        data = Path(good).read_bytes()
        Path(bad).write_bytes(data[: len(data) // 3])  # chop it up
        assert asyncio.run(stitch.verify_video(bad)) is False


def test_verify_rejects_missing_and_empty():
    with tempfile.TemporaryDirectory() as tmp:
        assert asyncio.run(stitch.verify_video(os.path.join(tmp, "nope.mp4"))) is False
        empty = os.path.join(tmp, "empty.mp4")
        Path(empty).touch()
        assert asyncio.run(stitch.verify_video(empty)) is False


@requires_ffmpeg
def test_verify_rejects_duration_shorter_than_expected():
    with tempfile.TemporaryDirectory() as tmp:
        clip = os.path.join(tmp, "short.mp4")
        _make_clip(clip, seconds=1)
        # claim we expected 10s from a 1s file -> input was dropped
        assert asyncio.run(stitch.verify_video(clip, expected_duration_sec=10.0)) is False


async def _add_chunk(store, path, related_event, category, created_at, device_id=1,
                     duration_ms=1000):
    fid = f"{category}-{os.path.basename(path)}"
    await store.upsert_media({
        "file_id": fid, "device_id": device_id, "related_event": related_event,
        "category": category, "media_path": path, "status": "ready",
        "duration_ms": duration_ms, "start_ts": created_at, "end_ts": created_at + 1,
        "size_bytes": os.path.getsize(path) if os.path.isfile(path) else 1,
        # Backdated on INSERT: the quiet-period logic is driven by created_at,
        # and nothing may rewrite it afterwards.
        "created_at": created_at,
    })


async def test_stitch_candidates_respects_quiet_period_and_min_chunks():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        now = 10_000.0
        # episode A: 3 chunks, long finished
        for i in range(3):
            await _add_chunk(store, f"/x/a{i}.mp4", "epA", "fullVideo", now - 1000 + i)
        # episode B: 2 chunks but one just arrived -> still recording
        await _add_chunk(store, "/x/b0.mp4", "epB", "fullVideo", now - 1000)
        await _add_chunk(store, "/x/b1.mp4", "epB", "fullVideo", now - 5)
        # episode C: a single chunk -> nothing to join
        await _add_chunk(store, "/x/c0.mp4", "epC", "fullVideo", now - 1000)

        found = await store.stitch_candidates(("fullVideo",), quiet_before_ts=now - 100)
        assert [e["related_event"] for e in found] == ["epA"]
        assert len(found[0]["chunks"]) == 3


async def test_stitch_candidates_never_mixes_categories():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        now = 10_000.0
        # same episode, two different streams — must stay separate, since the
        # substream has a different resolution/framerate entirely
        for i in range(2):
            await _add_chunk(store, f"/x/main{i}.mp4", "ep1", "fullVideo", now - 500 + i)
            await _add_chunk(store, f"/x/sub{i}.mp4", "ep1", "cloudDouble", now - 500 + i)

        found = await store.stitch_candidates(("fullVideo", "cloudDouble"),
                                              quiet_before_ts=now - 100)
        cats = sorted(e["category"] for e in found)
        assert cats == ["cloudDouble", "fullVideo"]
        for ep in found:
            assert {c["category"] for c in ep["chunks"]} == {ep["category"]}


async def test_stitch_candidates_skips_previously_failed():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        now = 10_000.0
        for i in range(2):
            await _add_chunk(store, f"/x/f{i}.mp4", "epF", "fullVideo", now - 500 + i)
        ids = [m["id"] for m in await store.media_for_retention("fullVideo")]
        await store.mark_stitch_failed(ids, "failed")
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=now - 100) == []


async def test_replace_chunks_with_stitched_is_atomic_swap():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        now = 10_000.0
        for i in range(3):
            await _add_chunk(store, f"/x/s{i}.mp4", "epS", "fullVideo", now - 500 + i)
        chunk_ids = [m["id"] for m in await store.media_for_retention("fullVideo")]

        await store.replace_chunks_with_stitched(chunk_ids, {
            "file_id": "stitched:epS:fullVideo", "device_id": 1,
            "related_event": "epS", "category": "fullVideo",
            "media_path": "/x/joined.mp4", "status": "ready",
            "size_bytes": 999, "stitch_state": "stitched",
        })
        rows = await store.media_for_retention("fullVideo")
        assert len(rows) == 1
        assert rows[0]["file_id"] == "stitched:epS:fullVideo"


@requires_ffmpeg
async def test_stitch_episode_end_to_end_replaces_chunks_and_keeps_one_playable_file():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        day_dir = os.path.join(media_root, "Dev", "Playback", "2026-07-22")
        os.makedirs(day_dir, exist_ok=True)

        paths = []
        for i in range(3):
            p = os.path.join(day_dir, f"chunk{i}.mp4")
            _make_clip(p, seconds=1)
            paths.append(p)
            await _add_chunk(store, p, "epE", "fullVideo", 1000.0 + i, duration_ms=1000)

        episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
        out = await stitch.stitch_episode(
            store, episode, media_root, work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is not None and os.path.isfile(out)
        # originals gone, one merged row left
        for p in paths:
            assert not os.path.exists(p) or p == out
        rows = await store.media_for_retention("fullVideo")
        assert len(rows) == 1
        assert rows[0]["file_id"] == "stitched:epE:fullVideo"
        assert rows[0]["media_path"] == out
        assert await stitch.verify_video(out, expected_duration_sec=3.0) is True


async def test_stitch_episode_keeps_chunks_when_output_is_unusable():
    """If verification fails the sources must survive — that's the whole
    reason verification runs before deletion."""
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        day_dir = os.path.join(media_root, "Dev", "Playback", "2026-07-22")
        os.makedirs(day_dir, exist_ok=True)
        paths = []
        for i in range(2):
            p = os.path.join(day_dir, f"junk{i}.mp4")
            Path(p).write_bytes(b"not really video")  # ffmpeg will refuse this
            paths.append(p)
            await _add_chunk(store, p, "epJ", "fullVideo", 1000.0 + i)

        episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
        out = await stitch.stitch_episode(
            store, episode, media_root, work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is None
        for p in paths:
            assert os.path.isfile(p), "chunks must be kept when stitching fails"
        # and marked so the sweeper doesn't retry them forever
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0) == []


async def test_reclassify_media_categories_fixes_old_rows():
    """A row stored under the previous (wrong) mapping must be corrected, so
    the substream stops sharing a category with the main recording."""
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        await store.upsert_media({"file_id": "old", "device_id": 1,
                                  "module_type": "CLOUD_DOUBLE", "category": "fullVideo",
                                  "status": "ready", "media_path": "/x/a.mp4"})
        await store.upsert_media({"file_id": "ok", "device_id": 1,
                                  "module_type": "CLOUD_STORAGE", "category": "fullVideo",
                                  "status": "ready", "media_path": "/x/b.mp4"})

        from petkit_local.events.ingest import _MODULE_TYPE_TO_CATEGORY
        changed = await store.reclassify_media_categories(_MODULE_TYPE_TO_CATEGORY)

        assert changed == 1
        assert (await store.get_media_by_file_id("old"))["category"] == "cloudDouble"
        assert (await store.get_media_by_file_id("ok"))["category"] == "fullVideo"
        # idempotent
        assert await store.reclassify_media_categories(_MODULE_TYPE_TO_CATEGORY) == 0


@requires_ffmpeg
def test_split_by_stream_separates_mismatched_chunk():
    """A single foreign chunk must not sink the whole episode — real data hit
    exactly this (26 x 1056x1056 plus one stray 528x528)."""
    with tempfile.TemporaryDirectory() as tmp:
        good = []
        for i in range(3):
            p = os.path.join(tmp, f"big{i}.mp4")
            _make_clip(p, seconds=1, size=64)
            good.append(p)
        odd = os.path.join(tmp, "small.mp4")
        _make_clip(odd, seconds=1, size=32)  # different resolution

        keep, outliers = asyncio.run(stitch.split_by_stream(good + [odd]))
        assert sorted(keep) == sorted(good)
        assert outliers == [odd]


@requires_ffmpeg
async def test_stitch_episode_excludes_mismatched_chunk_but_keeps_its_file():
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        day_dir = os.path.join(media_root, "Dev", "Playback", "2026-07-22")
        os.makedirs(day_dir, exist_ok=True)

        good = []
        for i in range(3):
            p = os.path.join(day_dir, f"ok{i}.mp4")
            _make_clip(p, seconds=1, size=64)
            good.append(p)
            await _add_chunk(store, p, "epX", "fullVideo", 1000.0 + i, duration_ms=1000)
        odd = os.path.join(day_dir, "odd.mp4")
        _make_clip(odd, seconds=1, size=32)
        await _add_chunk(store, odd, "epX", "fullVideo", 1003.0, duration_ms=1000)

        episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
        out = await stitch.stitch_episode(
            store, episode, media_root, work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is not None and os.path.isfile(out)
        # the odd one out survives untouched...
        assert os.path.isfile(odd), "excluded chunk must not be deleted"
        rows = {r["file_id"]: r for r in await store.media_for_retention("fullVideo")}
        assert "stitched:epX:fullVideo" in rows
        odd_row = next(r for fid, r in rows.items() if r["media_path"] == odd)
        assert odd_row["stitch_state"] == "excluded-stream-mismatch"
        # ...and the join covers only the 3 consistent chunks
        assert await stitch.verify_video(out, expected_duration_sec=3.0) is True


@requires_ffmpeg
async def test_stitch_recovers_by_dropping_an_undecodable_chunk():
    """A corrupted chunk must not sink the episode (real-device failure mode),
    and must be kept rather than deleted.

    This asserts the OUTCOME only. Which layer catches the chunk depends on the
    ffmpeg build: ffprobe 7.1 already fails to read it, so `split_by_stream`
    sets it aside and the retry pass never runs. The retry pass itself is
    pinned by `test_the_retry_pass_drops_a_chunk_that_probes_but_will_not_decode`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        day_dir = os.path.join(media_root, "Dev", "Playback", "2026-07-22")
        os.makedirs(day_dir, exist_ok=True)

        good = []
        for i in range(3):
            p = os.path.join(day_dir, f"g{i}.mp4")
            _make_clip(p, seconds=1, size=64)
            good.append(p)
            await _add_chunk(store, p, "epR", "fullVideo", 1000.0 + i, duration_ms=1000)

        # Intact header, damaged compressed payload — mirrors the corrupted
        # chunk seen in production.
        broken = os.path.join(day_dir, "broken.mp4")
        src = bytearray(Path(good[0]).read_bytes())
        mid = len(src) // 2
        src[mid:mid + 3000] = b"\xde\xad\xbe\xef" * 750
        Path(broken).write_bytes(bytes(src))
        await _add_chunk(store, broken, "epR", "fullVideo", 1003.0, duration_ms=1000)
        assert await stitch.is_decodable(broken) is False, "test fixture must be undecodable"

        episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
        assert len(episode["chunks"]) == 4
        out = await stitch.stitch_episode(
            store, episode, media_root, work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is not None, "should have recovered by dropping the bad chunk"
        assert await stitch.verify_video(out, expected_duration_sec=3.0) is True
        assert os.path.isfile(broken), "the dropped chunk must be kept, not deleted"


def test_concat_list_entry_escapes_single_quotes():
    """ffmpeg's tokenizer treats everything inside single quotes as literal,
    so a literal quote is written by closing, backslash-escaping and
    reopening — the `'\\''` sequence."""
    assert stitch._concat_list_entry("/m/a b.mp4") == "file '/m/a b.mp4'\n"
    assert stitch._concat_list_entry("/m/it's.mp4") == "file '/m/it'\\''s.mp4'\n"
    # backslashes are literal inside quotes and must be left alone
    assert stitch._concat_list_entry("/m/a\\b.mp4") == "file '/m/a\\b.mp4'\n"


def test_concat_list_entry_rejects_line_terminators_and_nul():
    """The demuxer reads the list line by line before it ever looks at
    quotes, so a newline in a path injects a whole extra directive. Nothing
    can escape it — the writer must refuse."""
    for bad in ("/m/a\nfile '/etc/passwd'\n", "/m/a\rb.mp4", "/m/a\x00b.mp4"):
        try:
            stitch._concat_list_entry(bad)
            assert False, f"expected UnsafeConcatPath for {bad!r}"
        except stitch.UnsafeConcatPath:
            pass


@requires_ffmpeg
def test_concat_videos_refuses_a_path_with_a_newline():
    """Defensive independently of media/layout.py's sanitizer: rows written by
    older builds are not guaranteed to have been sanitized."""
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.mp4")
        _make_clip(good, seconds=1)
        out = os.path.join(tmp, "out.mp4")
        ok = asyncio.run(stitch.concat_videos(
            [good, "/m/evil\nfile '/etc/passwd'"], out, work_dir=os.path.join(tmp, "work")))
        assert ok is False
        assert not os.path.exists(out)


@requires_ffmpeg
def test_concat_joins_paths_containing_single_quotes():
    """End-to-end proof the escaping is right, not just plausible."""
    with tempfile.TemporaryDirectory() as tmp:
        parts = []
        for i in range(2):
            p = os.path.join(tmp, f"Mruczek's clip {i}.mp4")
            _make_clip(p, seconds=1)
            parts.append(p)
        out = os.path.join(tmp, "joined.mp4")
        assert asyncio.run(stitch.concat_videos(
            parts, out, work_dir=os.path.join(tmp, "work"))) is True
        assert asyncio.run(stitch.verify_video(out, expected_duration_sec=2.0)) is True


@requires_ffmpeg
def test_concat_list_is_cleaned_up_and_named_after_its_output():
    """A stable, output-derived name means a run killed mid-concat leaves a
    file the next run for the same episode overwrites, not an orphan."""
    with tempfile.TemporaryDirectory() as tmp:
        parts = []
        for i in range(2):
            p = os.path.join(tmp, f"c{i}.mp4")
            _make_clip(p, seconds=1)
            parts.append(p)
        work = os.path.join(tmp, "work")
        out = os.path.join(tmp, "stitching_fullVideo_abc123.mp4")
        assert asyncio.run(stitch.concat_videos(parts, out, work_dir=work)) is True
        assert os.listdir(work) == []  # list removed, no temp files left behind


def test_episode_slug_is_stable_across_processes():
    """`hash()` of a str is seeded per process, so a temp file left by a
    crashed run could never be recognised by the next one."""
    code = (
        "from petkit_local.media import stitch;"
        "print(stitch._episode_slug({'related_event': '3_10000001_1784741818',"
        " 'category': 'fullVideo'}))"
    )
    env = dict(os.environ, PYTHONHASHSEED="0")
    first = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    env["PYTHONHASHSEED"] = "12345"
    second = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert first.returncode == 0 and second.returncode == 0, first.stderr + second.stderr
    assert first.stdout.strip() == second.stdout.strip() != ""


def test_episode_slug_separates_the_two_video_streams():
    """The substream shares its related_event with the main recording; if
    both landed on one temp name they would clobber each other."""
    base = {"related_event": "epA"}
    assert (stitch._episode_slug({**base, "category": "fullVideo"})
            != stitch._episode_slug({**base, "category": "cloudDouble"}))


@requires_ffmpeg
async def test_repeated_failed_stitches_do_not_accumulate_temp_files():
    """The temp name is derived from the episode, so a retry reuses it. With
    a per-process `hash()` every attempt left one more orphan in the work
    dir, and nothing could ever recognise them."""
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        day_dir = os.path.join(media_root, "Dev", "Playback", "2026-07-22")
        os.makedirs(day_dir, exist_ok=True)
        for i in range(3):
            p = os.path.join(day_dir, f"c{i}.mp4")
            _make_clip(p, seconds=1, size=64)
            # Claiming 100s per 1s chunk makes verification reject the join on
            # the duration ratio, so every attempt gets as far as writing the
            # temp file and then fails.
            await _add_chunk(store, p, "epT", "fullVideo", 1000.0 + i, duration_ms=100_000)

        work = os.path.join(tmp, "work")
        episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
        for _ in range(3):
            assert await stitch.stitch_episode(
                store, episode, media_root, work_dir=work, device_type="t5") is None
        assert os.listdir(work) == [], "failed attempts left temp files behind"


def test_claim_unique_path_never_hands_out_the_same_name_twice():
    from petkit_local.media.pipeline import _claim_unique_path
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "sub", "18-19-04 Toilet visit.mp4")
        first = _claim_unique_path(target)
        second = _claim_unique_path(target)
        third = _claim_unique_path(target)
        assert first == target
        assert len({first, second, third}) == 3
        assert second.endswith(" (2).mp4") and third.endswith(" (3).mp4")
        for p in (first, second, third):
            assert os.path.isfile(p)


# --- stitch_episode orchestration, without ffmpeg ---------------------------
#
# What these pin is the bookkeeping around the four media primitives: which
# chunks reach a join, which are retried without, and — because a stitch
# deletes its sources — which files are still on disk afterwards.


def _fake_media(monkeypatch, *, undecodable=(), probe_outliers=()):
    """Stand in for ffmpeg. Returns the list of joins attempted, in order.

    A join that contains an `undecodable` chunk fails verification, which is
    what a corrupt chunk does to a real one. `probe_outliers` are the chunks
    `split_by_stream` sets aside.
    """
    joins = []

    async def split(paths):
        return ([p for p in paths if p not in probe_outliers],
                [p for p in paths if p in probe_outliers])

    async def concat(paths, dst, work_dir):
        joins.append(list(paths))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        Path(dst).write_bytes(b"joined")
        return True

    async def verify(path, expected_duration_sec=None):
        return not any(p in undecodable for p in joins[-1])

    async def decodable(path):
        return path not in undecodable

    monkeypatch.setattr(stitch, "split_by_stream", split)
    monkeypatch.setattr(stitch, "concat_videos", concat)
    monkeypatch.setattr(stitch, "verify_video", verify)
    monkeypatch.setattr(stitch, "is_decodable", decodable)
    return joins


async def _dummy_episode(store, day_dir, related_event, n):
    """`n` chunk rows backed by files whose bytes do not matter."""
    os.makedirs(day_dir, exist_ok=True)
    paths = []
    for i in range(n):
        p = os.path.join(day_dir, f"{related_event}-{i}.mp4")
        Path(p).write_bytes(b"chunk %d" % i)
        paths.append(p)
        await _add_chunk(store, p, related_event, "fullVideo", 1000.0 + i)
    episode = (await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0))[0]
    return paths, episode


async def test_the_retry_pass_drops_a_chunk_that_probes_but_will_not_decode(monkeypatch):
    """The failure the retry exists for: a chunk well-formed enough to probe
    that still breaks the join (two writers racing on one filename)."""
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        paths, episode = await _dummy_episode(
            store, os.path.join(media_root, "Dev", "Playback", "2026-07-22"), "epR", 4)
        broken = paths[2]
        joins = _fake_media(monkeypatch, undecodable={broken})

        out = await stitch.stitch_episode(store, episode, media_root,
                                          work_dir=os.path.join(tmp, "work"), device_type="t5")

        good = [p for p in paths if p != broken]
        assert joins == [paths, good], "expected one full join, then one without the bad chunk"
        assert out is not None and os.path.isfile(out)
        assert os.path.isfile(broken), "the dropped chunk must be kept, not deleted"
        for p in good:
            assert not os.path.exists(p) or p == out
        rows = await store.media_for_retention("fullVideo")
        assert {r["media_path"] for r in rows} == {out, broken}
        # Flagged, so the sweeper does not keep reconsidering it.
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0) == []


async def test_a_retry_that_leaves_fewer_than_two_good_chunks_deletes_nothing(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        work = os.path.join(tmp, "work")
        paths, episode = await _dummy_episode(
            store, os.path.join(media_root, "Dev", "Playback", "2026-07-22"), "epB", 3)
        joins = _fake_media(monkeypatch, undecodable={paths[0], paths[1]})

        out = await stitch.stitch_episode(store, episode, media_root, work_dir=work,
                                          device_type="t5")

        assert out is None
        assert joins == [paths], "one good chunk is not worth a second join"
        for p in paths:
            assert os.path.isfile(p), "chunks must be kept when stitching fails"
        assert os.listdir(work) == [], "the failed join's temp file was left behind"
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0) == []


async def test_an_episode_whose_files_are_mostly_gone_is_not_joined(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        paths, episode = await _dummy_episode(
            store, os.path.join(media_root, "Dev", "Playback", "2026-07-22"), "epM", 2)
        os.remove(paths[1])
        joins = _fake_media(monkeypatch)

        out = await stitch.stitch_episode(store, episode, media_root,
                                          work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is None and joins == []
        assert os.path.isfile(paths[0])
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0) == []


async def test_an_episode_with_no_two_matching_streams_is_left_alone(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        store = await _store(tmp)
        media_root = os.path.join(tmp, "media")
        paths, episode = await _dummy_episode(
            store, os.path.join(media_root, "Dev", "Playback", "2026-07-22"), "epS", 3)
        joins = _fake_media(monkeypatch, probe_outliers={paths[1], paths[2]})

        out = await stitch.stitch_episode(store, episode, media_root,
                                          work_dir=os.path.join(tmp, "work"), device_type="t5")

        assert out is None and joins == []
        for p in paths:
            assert os.path.isfile(p)
        assert await store.stitch_candidates(("fullVideo",), quiet_before_ts=2000.0) == []


async def test_one_exploding_episode_does_not_stop_the_sweep(monkeypatch):
    """A single undecodable episode must not keep the media tree from ever
    converging — and the panel hears about the one that did join."""
    episodes = [
        {"device_id": 1, "related_event": "bad", "category": "fullVideo", "chunks": []},
        {"device_id": 1, "related_event": "good", "category": "cloudDouble", "chunks": []},
    ]

    class Store:
        async def stitch_candidates(self, categories, quiet_before_ts):
            return episodes

    class Registry:
        def get(self, device_id):
            return type("Device", (), {"device_type": "t5"})()

    class Hub:
        def __init__(self):
            self.published = []

        def publish(self, kind, device_id, text, detail=None):
            self.published.append((kind, device_id, detail))

    seen = []

    async def fake_stitch(store, ep, media_root, work_dir, device_type=""):
        seen.append((ep["related_event"], device_type))
        if ep["related_event"] == "bad":
            raise RuntimeError("boom inside one episode")
        return "/m/clip.mp4"

    monkeypatch.setattr(stitch, "stitch_episode", fake_stitch)
    hub = Hub()
    sweeper = stitch.EpisodeStitcher(Store(), Registry(), "/m", "/m/.raw", hub=hub)

    assert await sweeper.run_once() == 1
    assert seen == [("bad", "t5"), ("good", "t5")]
    assert hub.published == [("media", 1, {"stitched": True, "category": "cloudDouble"})]
