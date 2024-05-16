import tree_sitter_haskell as tshaskell
from tree_sitter import Language, Parser

# Load the compiled Haskell language library
HASKELL_LANGUAGE = Language(tshaskell.language())

# Initialize the parser
parser = Parser(HASKELL_LANGUAGE)

def detect_unsafe_perform_io(node, source_code):
    vulnerabilities = []
    if node.type == 'variable' and source_code[node.start_byte:node.end_byte] == 'unsafePerformIO':
        vulnerabilities.append({
            'type': 'Unsafe use of unsafePerformIO',
            'start': node.start_point,
            'end': node.end_point
        })
        print(f"Detected unsafePerformIO at {node.start_point}-{node.end_point}")
    
    for child in node.children:
        vulnerabilities.extend(detect_unsafe_perform_io(child, source_code))
    
    return vulnerabilities

def detect_unsafe_io(node, source_code):
    vulnerabilities = []
    if node.type == 'variable' and source_code[node.start_byte:node.end_byte] == 'IO':
        vulnerabilities.append({
            'type': 'Unsafe use of IO',
            'start': node.start_point,
            'end': node.end_point
        })
        print(f"Detected unsafe IO at {node.start_point}-{node.end_point}")
    
    for child in node.children:
        vulnerabilities.extend(detect_unsafe_io(child, source_code))
    
    return vulnerabilities

def detect_pattern_matching_failures(node, source_code):
    vulnerabilities = []
    if node.type == 'case' and node.children:
        case_clauses = [child for child in node.children if child.type == 'alternative']
        if len(case_clauses) < 2:
            vulnerabilities.append({
                'type': 'Partial pattern match',
                'start': node.start_point,
                'end': node.end_point
            })
            print(f"Detected partial pattern match at {node.start_point}-{node.end_point}")
    
    for child in node.children:
        vulnerabilities.extend(detect_pattern_matching_failures(child, source_code))
    
    return vulnerabilities

def detect_resource_leaks(node, source_code):
    vulnerabilities = []
    if node.type == 'apply' and 'openFile' in source_code[node.start_byte:node.end_byte]:
        vulnerabilities.append({
            'type': 'Potential resource leak (open without close)',
            'start': node.start_point,
            'end': node.end_point
        })
        print(f"Detected resource leak at {node.start_point}-{node.end_point}")
    
    for child in node.children:
        vulnerabilities.extend(detect_resource_leaks(child, source_code))
    
    return vulnerabilities


def analyze_haskell_code(source_code):
    tree = parser.parse(bytes(source_code, 'utf8'))
    root_node = tree.root_node

    vulnerabilities = []
    vulnerabilities.extend(detect_unsafe_perform_io(root_node, source_code))
    vulnerabilities.extend(detect_unsafe_io(root_node, source_code))
    vulnerabilities.extend(detect_pattern_matching_failures(root_node, source_code))
    vulnerabilities.extend(detect_resource_leaks(root_node, source_code))
    
    return vulnerabilities

if __name__ == "__main__":
    with open('example.hs', 'r') as f:
        source_code = f.read()
    
    vulnerabilities = analyze_haskell_code(source_code)

    for vulnerability in vulnerabilities:
        print(f"Vulnerability detected: {vulnerability['type']} at {vulnerability['start']} to {vulnerability['end']}")
