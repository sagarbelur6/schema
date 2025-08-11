import json
import re
import os

file_path = "../input_files/ediSchema.txt"
type_ = "824"

with open(file_path, "r", encoding="utf-8") as f:
    schema_text = f.read()

lines = [l.strip() for l in schema_text.splitlines() if l.strip()]

segment_defs = {}
group_defs = {}
message_structure = {}
current_segment = None
current_group_stack = []
current_area = None
current_message = None
composite_defs = {}
current_composite = None
occurence_obj = {}

# === Step 1: Parse Segment Element Definitions ===
for line in lines:
    m = re.match(r"^def segment (\w+)", line)
    if m:
        current_segment = m.group(1)
        segment_defs[current_segment] = []
    elif line.startswith("def") and "segment" not in line:
        current_segment = None
    else:
        m2 = re.match(r"^(\d{2}) (simpleElement|compositeElement) (\w+)", line)
        if current_segment and m2:
            elem_id = m2.group(3)
            segment_defs[current_segment].append(elem_id)
    m3 = re.match(r"^def compositeElement (\w+)", line)
    if m3:
        current_composite = m3.group(1)
        composite_defs[current_composite] = []
    elif line.startswith("def"):
        current_composite = None
    m4 = re.match(r"(\d{2}) simpleElement (\d+)", line)
    if current_composite and m4:
        num = m4.group(1)
        elem_id = m4.group(2)
        composite_defs[current_composite].append((num, elem_id))

# === Step 2: Parse Group Hierarchy ===
def get_last_index(input_array, input_segment):
    last_index = -1
    max_position = float('-inf')
    for idx, key in enumerate(input_array):
        if "___" in input_segment:
            segment = key
        else:
            segment = key.split('___')[0]
        if segment == input_segment and idx > max_position:
            max_position = idx
            last_index = idx
    return max_position

group_context = []
group_map = {}
map_data1 = []
for line in lines:
    m = re.match(r"^def segmentGroup (\w+)", line)
    if m:
        group_name = m.group(1)
        get_last_find_index = get_last_index(map_data1, group_name)
        segment_code = map_data1[get_last_find_index].split("___")[1] if get_last_find_index > -1 else ""
        group_context.append(f"{group_name}___{segment_code}___SegmentGroup")
        key = ".".join(group_context)
        if key not in group_map:
            group_map[key] = []
    else:
        m2 = re.match(r"(^\d+)\s+segment(Group)?\s+(\w+)", line)
        if m2:
            is_group = m2.group(2) == "Group"
            name = m2.group(3)
            code = m2.group(1)
            temp_name = f"{name}___{code}___{'SegmentGroup' if is_group else 'Segment'}"
            if is_group and temp_name not in map_data1:
                map_data1.append(temp_name)
            full_path = ".".join(group_context)
            if full_path not in group_map:
                group_map[full_path] = []
            group_map[full_path].append({
                "type": "group" if is_group else "segment",
                "name": temp_name
            })
        elif line == "}":
            if group_context:
                popped_data = group_context.pop()
                get_last_find_index = get_last_index(map_data1, popped_data)
                if popped_data and get_last_find_index > -1:
                    map_data1.pop(get_last_find_index)

# === Step 3: Parse Message Area ===
def resolve_path(obj, path):
    for key in path:
        if isinstance(obj, list):
            # If obj is a list, use the last dict in the list (or create one if empty)
            if not obj or not isinstance(obj[-1], dict):
                obj.append({})
            obj = obj[-1]
        if key not in obj:
            obj[key] = {}
        obj = obj[key]
    return obj

def build_composite_structure(name):
    # name is like "C040"
    result = {}
    fields = composite_defs.get(name, [])
    for i, (num, elem_id) in enumerate(fields):
        key = f"{elem_id}_{i+1}"
        position = str(i+1).zfill(2)
        result[key] = {
            "value": "",
            "position": position
        }
    return result

def build_segment_structure(name):
    if "___" in name:
        name = name.split("___")[0]
    result = {}
    fields = segment_defs.get(name, [])
    for i, field in enumerate(fields):
        if field in composite_defs:
            # Composite element: build its structure
            result[field] = build_composite_structure(field)
        else:
            key = f"{field}_{i+1}"
            position = str(i+1).zfill(2)
            result[key] = {
                "value": "",
                "position": position
            }
    return result

def build_group_structure(name, prefix=None):
    if prefix is None:
        prefix = name
    full_path = next((k for k in group_map if k.endswith(prefix)), None)
    contents = group_map.get(full_path, []) if full_path else []
    result = {}
    for entry in contents:
        if entry["type"] == "segment":
            result[entry["name"]] = build_segment_structure(entry["name"])
        else:
            result[entry["name"]] = [build_group_structure(entry["name"])]
    return result

current_path = []
map_data = []
for line in lines:
    m_msg = re.match(r"^def message (\d+)", line)
    if m_msg:
        msg_code = m_msg.group(1)
        current_message = msg_code
        message_structure[msg_code] = {}
    m_area = re.match(r"^def area (\d+)", line)
    if m_area:
        area_id = m_area.group(1)
        area_key = f"Area{area_id}"
        message_structure[current_message][area_key] = {}
        current_area = message_structure[current_message][area_key]
        current_path = [area_key]
    m_occ = re.match(r"(^\d+)\s+segment(Group)?\s+(\w+)\s+\[(\d+)\.\.(\d+)\]", line)
    if m_occ:
        is_group = m_occ.group(2) == "Group"
        name = m_occ.group(3)
        code = m_occ.group(1)
        min_occ = m_occ.group(4)
        max_occ = m_occ.group(5)
        temp_path = f"{name}___{code}___{'SegmentGroup' if is_group else 'Segment'}"
        occurence_obj[temp_path] = {"minOcc": min_occ, "maxOcc": max_occ}
    m_seg = re.match(r"^(\d+)\s+segment(Group)?\s+(\w+)", line)
    if m_seg:
        is_group = m_seg.group(2) == "Group"
        name = m_seg.group(3)
        code = m_seg.group(1)
        pointer = resolve_path(message_structure[current_message], current_path)
        temp_name = f"{name}___{code}___{'SegmentGroup' if is_group else 'Segment'}"
        if is_group:
            if temp_name not in map_data:
                map_data.append(temp_name)
            if isinstance(pointer, list):
                if not pointer or not isinstance(pointer[-1], dict):
                    pointer.append({})
                pointer[-1][temp_name] = [build_group_structure(temp_name)]
            else:
                pointer[temp_name] = [build_group_structure(temp_name)]
        else:
            if isinstance(pointer, list):
                if not pointer or not isinstance(pointer[-1], dict):
                    pointer.append({})
                pointer[-1][temp_name] = build_segment_structure(temp_name)
            else:
                pointer[temp_name] = build_segment_structure(temp_name)


    m_group = re.match(r"^def segmentGroup (\w+)", line)
    if m_group:
        name = m_group.group(1)
        get_last_find_index = get_last_index(map_data, name)
        segment_code = map_data[get_last_find_index].split("___")[1] if get_last_find_index > -1 else ""
        current_path.append(f"{name}___{segment_code}___SegmentGroup")
    elif line == "}":
        if current_path:
            popped_data = current_path.pop()
            get_last_find_index = get_last_index(map_data, popped_data)
            if popped_data and get_last_find_index > -1:
                map_data.pop(get_last_find_index)

# === Save Final Output ===
output_dir = "../output_files"
os.makedirs(output_dir, exist_ok=True)

with open(os.path.join(output_dir, f"edi.json"), "w", encoding="utf-8") as f:
    json.dump(message_structure, f, indent=2)
with open(os.path.join(output_dir, f"occurence.json"), "w", encoding="utf-8") as f:
    json.dump(occurence_obj, f, indent=2)
print(f"✅ Output saved to edi.json")
