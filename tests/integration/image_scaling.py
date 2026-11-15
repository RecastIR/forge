"""Measure the emitted resolver against synthetic PE relocation tables."""
import json
import os
from pathlib import Path
import subprocess

from pe_layout import Layout
from test_stack import FORGE, IMAGE, run


def image_stats(image, base, ir):
    return json.loads(run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--image-stats",
                          image, hex(base), ir))


def counted_resolver(ir):
    measured = ir.with_suffix(".visits.ll")
    measured.write_bytes(run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--count-resolver-blocks", ir))
    return measured


class ImageScaling:
    def test_counts_pointer_walking_resolver(self):
        # A linear scan can hoist its sole reference to the table and advance a
        # cursor. Counting table-name occurrences misses every subsequent probe.
        rows = 32
        contents = r"\00" * (rows - 1) + r"\01"
        ir = self.work / "linear-cursor.ll"
        ir.write_text(f'''target triple = "arm64-apple-macosx11.0.0"
@image.ranges = private constant [{rows} x i8] c"{contents}"

define internal ptr @forge_image_address(i64 %key) {{
entry:
  %first = getelementptr i8, ptr @image.ranges, i64 0
  %valid = icmp ule i64 %key, 1
  br i1 %valid, label %walk, label %fault
walk:
  %cursor = phi ptr [ %first, %entry ], [ %next, %walk ]
  %byte = load i8, ptr %cursor
  %wide = zext i8 %byte to i64
  %hit = icmp eq i64 %key, %wide
  %next = getelementptr i8, ptr %cursor, i64 1
  br i1 %hit, label %found, label %walk
found:
  ret ptr %cursor
fault:
  call void @llvm.trap()
  unreachable
}}
declare void @llvm.trap()

define i64 @forge_lifted(i64 %key, i64 %unused) {{
  %row = call ptr @forge_image_address(i64 %key)
  %byte = load i8, ptr %row
  %result = zext i8 %byte to i64
  ret i64 %result
}}
''')
        inputs = b"0 0\n1 0\n0 0\n"
        for exe in self.compile_variants(ir):
            self.assertEqual(run(exe, input=inputs), b"0\n1\n0\n")
        for exe in self.compile_variants(counted_resolver(ir)):
            visits = [int(line, 16) for line in run(exe, input=inputs).splitlines()]
            self.assertEqual(visits, [3, rows + 2, 3])
            self.assertGreater(visits[1], rows.bit_length() + 4)

        # Keep the same working scan, but move it out of the measured body.
        delegated = self.work / "delegated-cursor.ll"
        delegated.write_text(ir.read_text().replace("define internal ptr @forge_image_address(",
                                                    "define internal ptr @walk_rows(") + """
define internal ptr @forge_image_address(i64 %key) {
  %row = call ptr @walk_rows(i64 %key)
  ret ptr %row
}
""")
        for exe in self.compile_variants(delegated):
            self.assertEqual(run(exe, input=inputs), b"0\n1\n0\n")
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            counted_resolver(delegated)
        self.assertIn(b"unmeasured call in image resolver", failure.exception.stderr)

    def test_relocation_heavy_lookup(self):
        current = os.environ["FORGE_TEST_LIFT_CONTRACT"]
        previous = os.environ.get("FORGE_TEST_PREVIOUS_LIFT_CONTRACT")
        shapes = {}
        for fields in (8, 64, 512):
            image = Path(IMAGE).with_name(f"image-ranges-{fields}.exe")
            module = json.loads(run(FORGE, "inspect", image, "--format", "json"))["modules"][0]
            entry = module["exports"][0]["rva"]
            base = int(module["image_base_va"], 16) + 0x1000000
            selected = {s["name"]: s for s in module["sections"]
                        if s["name"] in (".ranges", ".rdata", ".pdata")}
            start = base + int(selected[".ranges"]["rva"], 16)
            extent = sum(s["virtual_size"] for s in selected.values())

            # Hit every interval, including ordinary bytes on both sides of each
            # protected HIGHLOW and the last DIR64 in the final relocation block.
            hits = [base + int(selected[s]["rva"], 16) for s in (".rdata", ".pdata")]
            layout = Layout(image.read_bytes())
            first_words = [layout.u32(layout.file_offset(addr-base)) for addr in hits]
            hits += [start] + [start + 16*i + 8 for i in range(fields)]
            inputs = b"".join(f"{addr:x} 0\n".encode() for addr in hits)
            remaining_words = b"".join(f"{start + 16*i:x} 0\n".encode() for i in range(1, fields))
            for label, contract in (("current", current), ("previous", previous)):
                if not contract:
                    continue
                command = (contract, "--emit-rebased", image, entry, hex(base))
                data = run(*command)
                self.assertEqual(data, run(*command))
                ir = self.work / f"ranges-{fields}-{label}.ll"
                ir.write_bytes(data)
                stats = image_stats(image, base, ir)
                self.assertEqual(stats["selected_sections"], len(selected))
                for key in ("budgeted_initialized_bytes", "emitted_initializer_bytes", "virtual_bytes"):
                    self.assertEqual(stats[key], extent)
                self.assertEqual(stats["intervals"], len(hits))
                self.assertEqual(stats["ir_bytes"], len(data))
                self.assertLessEqual(stats["resolver_blocks"], 10)
                shape = (stats["resolver_blocks"], stats["resolver_instructions"])
                self.assertEqual(shape, shapes.setdefault(label, shape))

                for exe in self.compile_variants(ir):
                    values = run(exe, input=inputs + remaining_words).splitlines()
                    expected = first_words + [0x78563412] + [start] * fields + [0x78563412] * (fields-1)
                    self.assertEqual([int(line, 16) for line in values], expected)
                    self.expect(exe, start + 9, 0, start >> 8)
                    for address in (start - 1, start + 1, start + 4, start + 16*fields - 3,
                                    start + 16*(fields//2) + 5, start + 16*(fields-1) + 1):
                        self.trap(exe, [(address, 0)])

                for exe in self.compile_variants(counted_resolver(ir)):
                    counts = [int(line, 16) for line in run(exe, input=inputs).splitlines()]
                    self.assertEqual(len(counts), len(hits))
                    self.assertGreater(min(counts), 0)
                    if label == "current":
                        # Entry, search exit, candidate and success add four visits.
                        self.assertLessEqual(max(counts), len(hits).bit_length() + 4)
                    stats["max_resolver_block_visits"] = max(counts)
                    if previous or os.environ.get("FORGE_IMAGE_METRICS"):
                        variant = "o2" if exe.stem.endswith(".o2") else "baseline"
                        print(json.dumps(dict(stats, build=label, fields=fields, variant=variant),
                                         sort_keys=True), flush=True)
