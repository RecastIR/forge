"""Measure the emitted resolver against synthetic PE relocation tables."""
import json
import os
from pathlib import Path
import re

from pe_layout import Layout
from test_stack import FORGE, IMAGE, run


def image_stats(image, base, ir):
    return json.loads(run(os.environ["FORGE_TEST_LIFT_CONTRACT"], "--image-stats",
                          image, hex(base), ir))


def count_probes(ir):
    # Instrument each actual table-row address calculation, including the final
    # candidate check. The untouched module is independently exercised first.
    sites = 0

    def increment(match):
        nonlocal sites
        sites += 1
        return (f"  %probes.{sites} = load volatile i64, ptr @probes\n"
                f"  %next.{sites} = add i64 %probes.{sites}, 1\n"
                f"  store volatile i64 %next.{sites}, ptr @probes\n" + match[0])

    text = re.sub(r"^  %[^ ]+ = getelementptr [^\n]*ptr @image\.ranges,[^\n]*",
                  increment, ir, flags=re.MULTILINE)
    if not sites or text.count("define i64 @forge_lifted(") != 1:
        raise ValueError("missing image-table probes or native entry in generated module")
    text = text.replace("define i64 @forge_lifted(", "define internal i64 @lookup(")
    return text + """
@probes = internal global i64 0
define i64 @forge_lifted(i64 %address, i64 %second) {
  store i64 0, ptr @probes
  call i64 @lookup(i64 %address, i64 %second)
  %count = load i64, ptr @probes
  ret i64 %count
}
"""


class ImageScaling:
    def test_relocation_heavy_lookup(self):
        current = os.environ["FORGE_TEST_LIFT_CONTRACT"]
        previous = os.environ.get("FORGE_TEST_PREVIOUS_LIFT_CONTRACT")
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
                self.assertEqual((stats["initialized_bytes"], stats["virtual_bytes"]), (extent, extent))
                self.assertEqual(stats["intervals"], len(hits))
                self.assertEqual(stats["ir_bytes"], len(data))
                self.assertLessEqual(stats["resolver_blocks"], 10)

                for exe in self.compile_variants(ir):
                    values = run(exe, input=inputs + remaining_words).splitlines()
                    expected = first_words + [0x78563412] + [start] * fields + [0x78563412] * (fields-1)
                    self.assertEqual([int(line, 16) for line in values], expected)
                    self.expect(exe, start + 9, 0, start >> 8)
                    for address in (start - 1, start + 1, start + 4, start + 16*fields - 3,
                                    start + 16*(fields//2) + 5, start + 16*(fields-1) + 1):
                        self.trap(exe, [(address, 0)])

                probe_ir = ir.with_suffix(".probes.ll")
                probe_ir.write_text(count_probes(data.decode()))
                for exe in self.compile_variants(probe_ir):
                    counts = [int(line, 16) for line in run(exe, input=inputs).splitlines()]
                    self.assertEqual(len(counts), len(hits))
                    self.assertGreater(min(counts), 0)
                    if label == "current":
                        self.assertLessEqual(max(counts), len(hits).bit_length() + 1)
                    stats["max_row_probes"] = max(counts)
                    if previous or os.environ.get("FORGE_IMAGE_METRICS"):
                        variant = "o2" if exe.stem.endswith(".o2") else "baseline"
                        print(json.dumps(dict(stats, build=label, fields=fields, variant=variant),
                                         sort_keys=True), flush=True)
