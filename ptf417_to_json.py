#!/usr/bin/env python3

"""
ptf417_to_json.py

Single-entry Python program to parse a combined schema text file (PTF-*.TXT)
that contains both EDI schema and XML schema DSL blocks, and generate
edi.json and xml.json matching the existing structure in this workspace.

If no PTF .txt file is found in the given input directory, the program exits
with an error and does not fall back to any other files.

Usage examples:
  - Default (auto-detect inputs, write to edi.json and xml.json):
      python ptf417_to_json.py

  - Explicit paths:
      python ptf417_to_json.py \
        --ptf /path/to/PTF-417.TXT \
        --edi-schema /workspace/ediSchema.txt \
        --xml-schema /workspace/xmlSchema.txt \
        --out-edi /workspace/edi.json \
        --out-xml /workspace/xml.json

Notes:
  - The EDI parser extracts the message 824 layout (areas, segment groups,
    segments, elements, composites) and renders a JSON skeleton with element
    positions and empty values, mirroring the current `edi.json`.
  - The XML parser reads the DSL-style schema (def Type {...}) and renders a
    single-instance skeleton tree where repeated constructs ([]) are represented
    as a single object with a `__loop` suffix, mirroring the current `xml.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

################################################################################
# Utilities
################################################################################

def read_text_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def write_json_file(path: str, data: Any) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def find_txt_input_file(input_dir: str) -> Optional[str]:
    """Auto-detect a single .txt/.TXT input file in the provided directory.
    Prefers names that look like PTF*.txt; ignores known schema files.
    Returns absolute path or None if not found.
    """
    if not os.path.isdir(input_dir):
        return None
    candidates: List[str] = []
    for name in os.listdir(input_dir):
        lower = name.lower()
        if not lower.endswith('.txt'):
            continue
        if lower in {'edischema.txt', 'xmlschema.txt'}:
            continue
        if lower.startswith('ptf') or lower.startswith('x12') or lower.startswith('417'):
            candidates.append(name)
    # Fallback to any .txt if no preferred names found
    if not candidates:
        for name in os.listdir(input_dir):
            lower = name.lower()
            if lower.endswith('.txt') and lower not in {'edischema.txt', 'xmlschema.txt'}:
                candidates.append(name)
    if not candidates:
        return None
    # Pick the first sorted candidate
    candidates.sort()
    return os.path.abspath(os.path.join(input_dir, candidates[0]))


################################################################################
# EDI schema parsing (from Extol-style DSL as seen in ediSchema.txt)
################################################################################

@dataclass
class EdiElement:
    position: int
    # Simple element: element_id is numeric string; Composite: composite_name
    element_id: Optional[str] = None
    composite_name: Optional[str] = None


@dataclass
class EdiSegmentDef:
    name: str
    elements: List[EdiElement] = field(default_factory=list)


@dataclass
class EdiCompositeDef:
    name: str
    elements: List[Tuple[int, str]] = field(default_factory=list)  # (position, simple_id)


@dataclass
class EdiAreaEntry:
    line_num: str  # like '0100'
    kind: str      # 'segment' or 'segmentGroup'
    name: str
    cardinality: str
    children: List['EdiAreaEntry'] = field(default_factory=list)


class EdiSchemaParser:
    def __init__(self, edi_text: str) -> None:
        self.text = edi_text
        self.segment_defs: Dict[str, EdiSegmentDef] = {}
        self.composite_defs: Dict[str, EdiCompositeDef] = {}
        self.message_areas: Dict[str, List[EdiAreaEntry]] = {}
        self.message_number: Optional[str] = None

    def parse(self) -> None:
        self._parse_composites()
        self._parse_segments()
        self._parse_message_any()

    # --- Low-level helpers ---

    @staticmethod
    def _strip_comments(s: str) -> str:
        # Remove /* ... */ comments
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
        return s

    def _find_blocks(self, pattern: str) -> List[Tuple[str, int, int]]:
        # Return list of (name, start_idx, end_idx) for blocks like: def segment NAME { ... }
        blocks: List[Tuple[str, int, int]] = []
        for m in re.finditer(pattern, self.text):
            name = m.group(1)
            start = m.end()
            end = self._find_matching_brace(start)
            if end != -1:
                blocks.append((name, start, end))
        return blocks

    def _find_matching_brace(self, start_idx: int) -> int:
        return self._find_matching_brace_in_text(self.text, start_idx)

    def _find_matching_brace_in_text(self, text: str, start_idx: int) -> int:
        depth = 0
        i = start_idx
        while i < len(text):
            ch = text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                if depth == 0:
                    return i
                depth -= 1
            i += 1
        return -1

    # --- Parse composite element definitions ---

    def _parse_composites(self) -> None:
        pattern = r"def\s+compositeElement\s+(\w+)\s*\{"
        for name, start, end in self._find_blocks(pattern):
            body = self.text[start:end]
            comp = EdiCompositeDef(name=name)
            for line in body.splitlines():
                line = line.strip()
                m = re.match(r"^(\d{1,2})\s+simpleElement\s+(\d+)\b", line)
                if m:
                    pos = int(m.group(1))
                    simple_id = m.group(2)
                    comp.elements.append((pos, simple_id))
            # Sort by position to ensure stable ordering
            comp.elements.sort(key=lambda t: t[0])
            self.composite_defs[name] = comp

    # --- Parse segment definitions ---

    def _parse_segments(self) -> None:
        pattern = r"def\s+segment\s+(\w+)\s*\{"
        for name, start, end in self._find_blocks(pattern):
            body = self.text[start:end]
            seg = EdiSegmentDef(name=name)
            for line in body.splitlines():
                line = line.strip()
                # 01 simpleElement 143 [1..1]
                m1 = re.match(r"^(\d{1,2})\s+simpleElement\s+(\d+)\b", line)
                if m1:
                    pos = int(m1.group(1))
                    element_id = m1.group(2)
                    seg.elements.append(EdiElement(position=pos, element_id=element_id))
                    continue
                # 04 compositeElement C040 [0..1]
                m2 = re.match(r"^(\d{1,2})\s+compositeElement\s+([A-Za-z0-9]+)\b", line)
                if m2:
                    pos = int(m2.group(1))
                    comp_name = m2.group(2)
                    seg.elements.append(EdiElement(position=pos, composite_name=comp_name))
                    continue
            seg.elements.sort(key=lambda e: e.position)
            self.segment_defs[name] = seg

    # --- Parse the message area structure for any message number ---

    def _parse_message_any(self) -> None:
        # Locate a message block: def message <num> { ... }
        msg_header = re.search(r"def\s+message\s+(\d+)\s*\{", self.text)
        if not msg_header:
            return
        self.message_number = msg_header.group(1)
        start = msg_header.end()
        end = self._find_matching_brace(start)
        if end == -1:
            return
        body = self.text[start:end]

        # Parse areas: def area 1 { ... }, def area 2 { ... }, etc.
        area_pattern = r"def\s+area\s+(\d+)\s*\{"
        areas: Dict[str, List[EdiAreaEntry]] = {}
        for am in re.finditer(area_pattern, body):
            area_num = am.group(1)
            astart_rel = am.end()
            aend_rel = self._find_matching_brace_in_text(body, astart_rel)
            if aend_rel == -1:
                continue
            abody = body[astart_rel:aend_rel]
            entries = self._parse_area_entries(abody)
            areas[area_num] = entries
        self.message_areas = areas

    def _parse_area_entries(self, abody: str) -> List[EdiAreaEntry]:
        entries: List[EdiAreaEntry] = []
        # Strip nested def segmentGroup blocks from this level so their internal
        # 4-digit listing lines don't get treated as top-level entries here.
        header = self._strip_segment_group_defs(abody)
        lines = [ln.strip() for ln in header.splitlines() if ln.strip()]
        i = 0
        while i < len(lines):
            line = lines[i]
            # e.g. 0100 segment ST [1..1]
            m_seg = re.match(r"^(\d{4})\s+segment\s+(\w+)\s*(\[[^\]]*\])?", line)
            if m_seg:
                entries.append(EdiAreaEntry(
                    line_num=m_seg.group(1),
                    kind='segment',
                    name=m_seg.group(2),
                    cardinality=m_seg.group(3) or ''
                ))
                i += 1
                continue

            # e.g. 0300 segmentGroup N1 []  followed by def segmentGroup N1 { ... }
            m_sg = re.match(r"^(\d{4})\s+segmentGroup\s+(\w+)\s*(\[[^\]]*\])?", line)
            if m_sg:
                line_num = m_sg.group(1)
                name = m_sg.group(2)
                card = m_sg.group(3) or ''
                # Find the group's definition block within the full abody
                sub_m = re.search(rf"def\s+segmentGroup\s+{re.escape(name)}\s*\{{", abody)
                if sub_m:
                    sub_start = sub_m.end()
                    sub_end = self._find_matching_brace_in_text(abody, sub_start)
                    if sub_end != -1:
                        sub_body = abody[sub_start:sub_end]
                        children = self._parse_area_entries(sub_body)
                        entries.append(EdiAreaEntry(
                            line_num=line_num,
                            kind='segmentGroup',
                            name=name,
                            cardinality=card,
                            children=children
                        ))
                        i += 1
                        continue
                # If we cannot find the formal def block, still record as empty group
                entries.append(EdiAreaEntry(
                    line_num=line_num,
                    kind='segmentGroup',
                    name=name,
                    cardinality=card,
                    children=[]
                ))
                i += 1
                continue
            i += 1
        return entries

    def _strip_segment_group_defs(self, text: str) -> str:
        # Remove all occurrences of: def segmentGroup NAME { ... }
        out = []
        i = 0
        while i < len(text):
            m = re.search(r"def\s+segmentGroup\s+\w+\s*\{", text[i:])
            if not m:
                out.append(text[i:])
                break
            start = i + m.start()
            # append up to start
            out.append(text[i:start])
            block_start = i + m.end()
            block_end = self._find_matching_brace_in_text(text, block_start)
            if block_end == -1:
                # malformed; stop removal
                out.append(text[block_start:])
                break
            # skip the entire block including trailing '}'
            i = block_end + 1
        return ''.join(out)

    # --- Render to JSON matching existing edi.json structure ---

    def render_edi_json(self) -> Dict[str, Any]:
        # Render using the detected message number (e.g., '824', '417')
        msg = self.message_number or 'MSG'
        result: Dict[str, Any] = {msg: {}}
        for area_num, entries in sorted(self.message_areas.items(), key=lambda t: int(t[0])):
            area_key = f"Area{area_num}"
            result[msg][area_key] = self._render_area(entries)
        return result

    def _render_area(self, entries: List[EdiAreaEntry]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for entry in entries:
            if entry.kind == 'segment':
                seg_key = f"{entry.name}___{entry.line_num}___Segment"
                out[seg_key] = self._render_segment(entry.name)
            elif entry.kind == 'segmentGroup':
                grp_key = f"{entry.name}___{entry.line_num}___SegmentGroup"
                # As per existing edi.json, groups are arrays with a single object sample
                grp_obj: Dict[str, Any] = self._render_group(entry)
                out[grp_key] = [grp_obj]
        return out

    def _render_group(self, group: EdiAreaEntry) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for child in group.children:
            if child.kind == 'segment':
                seg_key = f"{child.name}___{child.line_num}___Segment"
                out[seg_key] = self._render_segment(child.name)
            elif child.kind == 'segmentGroup':
                grp_key = f"{child.name}___{child.line_num}___SegmentGroup"
                out[grp_key] = [self._render_group(child)]
        return out

    def _render_segment(self, seg_name: str) -> Dict[str, Any]:
        seg = self.segment_defs.get(seg_name)
        if not seg:
            return {}
        out: Dict[str, Any] = {}
        for elem in seg.elements:
            if elem.element_id is not None:
                key = f"{elem.element_id}_{elem.position}"
                out[key] = {"value": "", "position": f"{elem.position:02d}"}
            elif elem.composite_name is not None:
                comp = self.composite_defs.get(elem.composite_name)
                comp_key = elem.composite_name
                comp_obj: Dict[str, Any] = {}
                if comp:
                    for cpos, simple_id in sorted(comp.elements, key=lambda t: t[0]):
                        ckey = f"{simple_id}_{cpos}"
                        comp_obj[ckey] = {"value": "", "position": f"{cpos:02d}"}
                out[comp_key] = comp_obj
        return out


################################################################################
# XML schema parsing (from JS/DSL string as seen in xmlSchema.txt)
################################################################################

@dataclass
class XmlField:
    name: str
    type_name: Optional[str]  # None for String
    is_list: bool


@dataclass
class XmlType:
    name: str
    fields: List[XmlField] = field(default_factory=list)


class XmlSchemaParser:
    def __init__(self, xml_text: str) -> None:
        self.text = xml_text
        self.types: Dict[str, XmlType] = {}

    def parse(self) -> None:
        # If it's the JS wrapper with export const schemaInput = `...` extract the inner DSL
        dsl = self._extract_dsl(self.text)
        self._parse_types(dsl)

    def _extract_dsl(self, text: str) -> str:
        m = re.search(r"schemaInput\s*=\s*`([\s\S]*?)`;\s*$", text, re.MULTILINE)
        if m:
            return m.group(1)
        return text

    def _parse_types(self, dsl: str) -> None:
        # Find all def TypeName { ... }
        for m in re.finditer(r"def\s+(\w+)\s*\{", dsl):
            type_name = m.group(1)
            start = m.end()
            end = self._find_matching_brace(dsl, start)
            if end == -1:
                continue
            body = dsl[start:end]
            xml_type = XmlType(name=type_name)
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                # Match attribute field:  _FIELD String ( ... ) ;
                if re.match(r"^[A-Za-z0-9_]+\s+String\b", line):
                    field_name = line.split()[0]
                    xml_type.fields.append(XmlField(name=field_name, type_name=None, is_list=False))
                    continue
                # Match nested type field:  Child Type ;  or  Child Type [] ;
                m2 = re.match(r"^([A-Za-z0-9_]+)\s+([A-Za-z0-9_$]+)\s*(\[\])?\s*;", line)
                if m2:
                    field_name = m2.group(1)
                    ref_type = m2.group(2)
                    is_list = m2.group(3) is not None
                    xml_type.fields.append(XmlField(name=field_name, type_name=ref_type, is_list=is_list))
                    continue
            self.types[type_name] = xml_type

    def _find_matching_brace(self, text: str, start_idx: int) -> int:
        depth = 0
        i = start_idx
        while i < len(text):
            ch = text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                if depth == 0:
                    return i
                depth -= 1
            i += 1
        return -1

    # --- Render to JSON matching existing xml.json structure ---

    def render_xml_json(self) -> Dict[str, Any]:
        # Root type is LIST
        if 'LIST' not in self.types:
            # Some PTFs might embed only the inner DSL; still expect LIST
            return {}
        root = self._instantiate_type('LIST')
        return { 'LIST': root }

    def _instantiate_type(self, type_name: str) -> Dict[str, Any]:
        t = self.types.get(type_name)
        if not t:
            return {}
        obj: Dict[str, Any] = {}
        for field in t.fields:
            if field.type_name is None:
                # Attribute (String)
                obj[field.name] = ""
            else:
                # Nested type
                nested = self._instantiate_nested(field.type_name)
                if field.is_list:
                    # Use __loop key and represent a single object (not an array), matching xml.json
                    obj[f"{field.name}__loop"] = nested
                else:
                    obj[field.name] = nested
        return obj

    def _instantiate_nested(self, type_name: str) -> Any:
        # Some schema uses type names with namespaces like Stglogistics824JSON$GS
        # The type definition is referenced without the namespace prefix in the DSL.
        base_name = type_name.split('$')[-1]
        nested_obj = self._instantiate_type(base_name)
        return nested_obj


################################################################################
# Combined parser/orchestrator
################################################################################

class PtfOrchestrator:
    def __init__(self, ptf_path: Optional[str]) -> None:
        self.ptf_path = ptf_path

    def load_sources(self) -> Tuple[str, str]:
        # Require a PTF .txt file
        if not self.ptf_path or not os.path.exists(self.ptf_path):
            raise FileNotFoundError("No PTF .txt file found. Provide --ptf or --input-dir with a .txt file.")
        ptf = read_text_file(self.ptf_path)
        # Extract XML DSL block if present
        xml_part = ''
        mxml = re.search(r"schemaInput\s*=\s*`([\s\S]*?)`;", ptf)
        if mxml:
            xml_part = mxml.group(1)
        # Remove XML part from EDI text to avoid confusing the EDI parser
        edi_part = ptf
        if xml_part:
            edi_part = ptf.replace(xml_part, '')
        return edi_part, xml_part


################################################################################
# Main
################################################################################

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Parse PTF-*.TXT (417 or other) or separate schemas to generate edi.json and xml.json in the input folder")
    parser.add_argument('--ptf', dest='ptf', default=None, help='Path to combined PTF .TXT containing both EDI and XML schema')
    parser.add_argument('--input-dir', dest='input_dir', default=None, help='Directory to auto-detect a single .txt input file (defaults to CWD)')
    parser.add_argument('--out-edi', dest='out_edi', default=None, help='Optional explicit output path for EDI JSON (overrides same-folder rule)')
    parser.add_argument('--out-xml', dest='out_xml', default=None, help='Optional explicit output path for XML JSON (overrides same-folder rule)')

    args = parser.parse_args(argv)

    # Auto-detect PTF input if not explicitly provided
    ptf_path = args.ptf
    if ptf_path is None:
        search_dir = args.input_dir or os.getcwd()
        ptf_path = find_txt_input_file(search_dir)

    # Determine output locations (same folder as input file unless overridden)
    out_edi = args.out_edi
    out_xml = args.out_xml
    if ptf_path and (out_edi is None or out_xml is None):
        base_dir = os.path.dirname(os.path.abspath(ptf_path))
        if out_edi is None:
            out_edi = os.path.join(base_dir, 'edi.json')
        if out_xml is None:
            out_xml = os.path.join(base_dir, 'xml.json')

    orchestrator = PtfOrchestrator(ptf_path)
    edi_text, xml_text = orchestrator.load_sources()

    # EDI parse and render
    edi_parser = EdiSchemaParser(edi_text)
    edi_parser.parse()
    edi_json = edi_parser.render_edi_json()

    # XML parse and render
    xml_parser = XmlSchemaParser(xml_text)
    xml_parser.parse()
    xml_json = xml_parser.render_xml_json()

    if out_edi is None or out_xml is None:
        # As a last resort (no PTF and no outputs provided), write to CWD
        cwd = os.getcwd()
        out_edi = out_edi or os.path.join(cwd, 'edi.json')
        out_xml = out_xml or os.path.join(cwd, 'xml.json')

    # Write outputs
    write_json_file(out_edi, edi_json)
    write_json_file(out_xml, xml_json)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())