import argparse
import re
from pathlib import Path
from xml.etree import ElementTree
from zipfile import ZipFile


def main():
    parser = argparse.ArgumentParser(description="Read the original CC-11 authorization")
    parser.add_argument("document", nargs="?", type=Path, default=(
        Path(__file__).parent / "files" / "CC-11_excursion_directive.docx"
    ))
    with ZipFile(parser.parse_args().document) as document:
        root = ElementTree.fromstring(document.read("word/document.xml"))
    namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    for paragraph in root.findall(".//w:p", namespace):
        deleted = "".join(node.text or "" for node in paragraph.findall(
            ".//w:del/w:r/w:delText", namespace
        ))
        if "MUST NOT be redistributed" in deleted:
            flag = re.search(r"CSCTF\{[^}]+\}", deleted)
            if flag:
                print(flag.group())
                return
    raise ValueError("No flag in the deleted quarantine clause")


if __name__ == "__main__":
    main()
