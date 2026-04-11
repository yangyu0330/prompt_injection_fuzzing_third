import sys
import zipfile
import xml.etree.ElementTree as ET

def read_docx(path):
    try:
        with zipfile.ZipFile(path) as docx:
            tree = ET.XML(docx.read('word/document.xml'))
            namespaces = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            text = [node.text for node in tree.findall('.//w:t', namespaces) if node.text]
            print(''.join(text))
    except Exception as e:
        print(f"Error: {e}")

if len(sys.argv) > 1:
    read_docx(sys.argv[1])
