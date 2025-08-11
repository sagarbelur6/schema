import json
import re
import os

# Load your schema DSL as a string (replace with file read if needed)
from pathlib import Path

# Example: Load schema DSL from a file
with open("../input_files/jsonSchema.txt", "r", encoding="utf-8") as f:
    schema_input = f.read()

type_defs = {}
current_type = None

def_regex = re.compile(r"^def\s+(\w+)\s*{")
field_regex = re.compile(r"^([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_.\[\]$]+)\s*(\[\])?\s*")

lines = [line.strip() for line in schema_input.splitlines() if line.strip()]

for raw in lines:
    m_def = def_regex.match(raw)
    if m_def:
        type_name = m_def.group(1)
        current_type = type_name
        type_defs[type_name] = []
    elif raw == "}":
        current_type = None
    elif current_type:
        m_field = field_regex.match(raw)
        if m_field:
            name, full_type, loop = m_field.groups()
            if loop == "[]":
                type_defs[current_type].append({"name": name + "__loop", "type": full_type})
            else:
                type_defs[current_type].append({"name": name, "type": full_type})

def resolve_type(raw_type):
    is_array = raw_type.endswith("[]")
    base_type = raw_type[:-2] if is_array else raw_type
    type_name = base_type.split(".")[-1].split("$")[-1]
    return type_name, is_array

def build_object(type_name):
    # Remove __loop if present
    base_type_name = type_name.split("__")[0]
    defn = type_defs.get(base_type_name)
    if not defn:
        return ""
    obj = {}
    for field in defn:
        name = field["name"]
        field_type = field["type"]
        field_type_name, is_array = resolve_type(field_type)
        is_primitive = name.startswith("_")
        if is_primitive:
            obj[name] = ""
        else:
            nested = build_object(field_type_name)
            obj[name] = [nested] if is_array else nested
    return obj

# Build root JSON (from LIST)
output_json = {
    "LIST": build_object("LIST")
}

output_dir = "../output_files"
os.makedirs(output_dir, exist_ok=True)

# Save output
with open(os.path.join(output_dir, "xml.json"), "w", encoding="utf-8") as f:
    json.dump(output_json, f, indent=2)

print("✅ JSON structure written to xml.json")
