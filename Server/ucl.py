import os
import re
import tempfile
from pathlib import Path
import traceback
import git
from tree_sitter_languages import get_parser, get_language
import shutil  # Added for cleanup consistency
import stat  # Added for cleanup consistency


class UCLGenerator:
    """
    Unified Code Language (UCL) file generator that parses codebases into a simplified structure,
    highlighting class names, function names, function calls, errors raised, docstrings and imports.
    """

    # Language parsers and file extensions mapping
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.pde': 'java',  # processing lib
        '.c': 'c',
        '.cpp': 'cpp',
        '.go': 'go',
        '.rb': 'ruby',
        '.php': 'php',
        '.rs': 'rust',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.sh': 'bash',
        '.md': 'markdown',
    }

    # Files to ignore
    IGNORE_PATTERNS = [
        r'__pycache__',
        r'\.git',
        r'\.vscode',
        r'\.idea',
        r'node_modules',
        r'\.env',
        r'\.DS_Store',
        r'.*\.pyc$',
        r'.*\.log$',
        r'venv',
        r'dist',
        r'build',
        r'\.cache'
    ]

    def __init__(self, logger=None):
        self.parsers = {}
        self.queries = {}
        self.logger = logger
        self._initialize_parsers()

    def log(self, message):
        """Log a message using the logger or print to console."""
        if self.logger:
            self.logger(message)
        else:
            print(message)

    def _initialize_parsers(self):
        """Initialize parsers for supported languages."""
        for ext, lang in self.LANGUAGE_MAP.items():
            try:
                self.parsers[ext] = get_parser(lang)
                self._generate_queries(ext, lang)
                self.log(f"Initialized parser for {lang}")
            except Exception as e:
                self.log(f"Warning: Could not initialize parser for {lang}: {e}")

    def _generate_queries(self, ext, lang):
        """Generate language-specific queries for tree-sitter."""
        language = get_language(lang)

        # Store queries for each language
        self.queries[ext] = {}

        # Common query patterns mapped to language specifics
        # --- Queries remain the same as provided ---
        if lang == 'python':
            self.queries[ext]['import'] = language.query("""
                (import_statement) @import
                (import_from_statement) @import
            """)
            self.queries[ext]['class'] = language.query("""
                (class_definition
                    name: (identifier) @class.name
                    body: (block) @class.body
                ) @class.def
            """)
            self.queries[ext]['class_attribute'] = language.query("""
                (class_definition
                    body: (block 
                        (expression_statement
                            (assignment
                                left: (identifier) @attribute.name
                            )
                        )
                    )
                )
            """)
            self.queries[ext]['function'] = language.query("""
                (function_definition
                    name: (identifier) @function.name
                    parameters: (parameters) @function.parameters
                    body: (block) @function.body
                ) @function.def
            """)
            self.queries[ext]['call'] = language.query("""
                (call 
                    function: (identifier) @call.name
                ) @call
                (call 
                    function: (attribute
                        object: (identifier) @call.object
                        attribute: (identifier) @call.method
                    )
                ) @call
            """)
            self.queries[ext]['raise'] = language.query("""
                (raise_statement) @raise
            """)
            self.queries[ext]['docstring'] = language.query("""
                (function_definition
                    body: (block . (expression_statement (string)) @docstring)
                ) @function_with_docstring

                (class_definition
                    body: (block . (expression_statement (string)) @docstring)
                ) @class_with_docstring
            """)
            self.queries[ext]['comment'] = language.query("""
                (comment) @comment
            """)

        elif lang in ['javascript', 'typescript']:
            self.queries[ext]['import'] = language.query("""
                (import_statement) @import
                (import_clause) @import
            """)
            self.queries[ext]['class'] = language.query("""
                (class_declaration
                    name: (identifier) @class.name
                    body: (class_body) @class.body
                ) @class.def
            """)
            self.queries[ext]['function'] = language.query("""
                (function_declaration
                    name: (identifier) @function.name
                    parameters: (formal_parameters)? @function.parameters
                    body: (statement_block) @function.body
                ) @function.def

                (method_definition
                    name: (property_identifier) @function.name
                    parameters: (formal_parameters)? @function.parameters
                    body: (statement_block) @function.body
                ) @function.def

                (arrow_function
                    parameters: (formal_parameters)? @function.parameters
                    body: [ (statement_block) (expression) ] @function.body
                ) @function.def # Note: Arrow functions might lack a direct @function.name capture easily
            """)
            self.queries[ext]['call'] = language.query("""
                (call_expression
                    function: (identifier) @call.name
                ) @call

                (call_expression
                    function: (member_expression
                        object: (_) @call.object  # Use (_) to capture various object types
                        property: (property_identifier) @call.method
                    )
                ) @call
            """)
            self.queries[ext]['comment'] = language.query("""
                (comment) @comment
            """)
            self.queries[ext]['class_attribute'] = language.query("""
                (class_body
                    (field_definition
                        name: (property_identifier) @property.name
                        value: (_)? @property.value
                    ) @property.def
                )
            """)

        elif lang == 'java':
            self.queries[ext]['import'] = language.query("""
                (import_declaration) @import
            """)
            self.queries[ext]['class'] = language.query("""
                (class_declaration
                    name: (identifier) @class.name
                    body: (class_body) @class.body
                ) @class.def
            """)
            self.queries[ext]['class_attribute'] = language.query("""
                (class_declaration
                    body: (class_body
                        (field_declaration
                            declarator: (variable_declarator
                                name: (identifier) @attribute.name
                            )
                        )
                    )
                )
            """)
            self.queries[ext]['function'] = language.query("""
                (method_declaration
                    name: (identifier) @function.name
                    parameters: (formal_parameters) @function.parameters
                    body: (block) @function.body
                ) @function.def
            """)
            self.queries[ext]['call'] = language.query("""
                (method_invocation
                    name: (identifier) @call.name
                ) @call

                (method_invocation
                    object: (_) @call.object # Use (_) for various object types
                    name: (identifier) @call.method
                ) @call
            """)
            self.queries[ext]['comment'] = language.query("""
                (comment) @comment
            """)
            # Java doesn't have explicit 'raise' like Python, 'throw' is used
            self.queries[ext]['raise'] = language.query("""
                (throw_statement) @raise
            """)
            # Java uses Javadoc comments
            self.queries[ext]['docstring'] = language.query("""
                (block_comment) @docstring
            """)  # This is a simplification, might capture non-javadoc comments too

    def clone_repository(self, repo_url, target_dir=None):
        """Clone a repository from GitHub."""
        if target_dir is None:
            target_dir = tempfile.mkdtemp()

        self.log(f"Cloning repository {repo_url} to {target_dir}...")
        try:
            git.Repo.clone_from(repo_url, target_dir)
            return target_dir
        except Exception as e:
            raise Exception(f"Failed to clone repository: {e}")

    def should_ignore_file(self, file_path):
        """Check if a file should be ignored based on patterns."""
        for pattern in self.IGNORE_PATTERNS:
            if re.search(pattern, str(file_path).replace(os.sep, '/')):  # Use forward slashes for regex consistency
                return True
        return False

    def get_file_structure(self, repo_dir):
        """Get the file structure of a repository as a list of Path objects."""
        file_structure = []
        root_path = Path(repo_dir)

        for path in root_path.glob("**/*"):
            relative_path = path.relative_to(root_path)
            if path.is_file() and not self.should_ignore_file(relative_path):
                file_structure.append(relative_path)

        return sorted(file_structure)

    def build_tree(self, paths):
        """Build a nested dictionary representing the folder structure."""
        tree = {}
        for path in paths:
            parts = path.parts
            subtree = tree
            for i, part in enumerate(parts):
                if i == len(parts) - 1:  # It's a file
                    subtree = subtree.setdefault(part, None)  # Use None to indicate a file
                else:  # It's a directory
                    subtree = subtree.setdefault(part, {})
        return tree

    def print_tree(self, tree, indent=0):
        """Return a list of lines representing the tree structure."""
        lines = []
        # Sort keys, prioritizing folders (dictionaries) over files (None value)
        sorted_keys = sorted(tree.keys(), key=lambda k: (isinstance(tree[k], dict), k))

        for name in sorted_keys:
            is_folder = isinstance(tree[name], dict)
            prefix = "  " * indent
            if is_folder:
                lines.append(prefix + f"{name}/")
                lines.extend(self.print_tree(tree[name], indent + 1))
            else:
                lines.append(prefix + name)
        return lines

    def parse_file(self, file_path):
        """Parse a file and extract its components based on file type."""
        extension = os.path.splitext(file_path)[1]
        if extension not in self.parsers:
            return {"file": str(file_path), "message": "File type not supported"}

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            parser = self.parsers[extension]
            tree = parser.parse(content)

            result = {
                "file": str(file_path),
                "imports": self._extract_imports(tree.root_node, extension),
                "classes": self._extract_classes(tree.root_node, extension, content),
                "functions": self._extract_functions(tree.root_node, extension, content),
            }

            return result
        except Exception as e:
            self.log(f"Error parsing {file_path}: {e}\n{traceback.format_exc()}")  # Added traceback
            return {"file": str(file_path), "error": str(e)}

    def _extract_class_attributes(self, node, extension):
        """Extract class attributes from a node."""
        attributes = []

        if not node or extension not in self.queries or 'class_attribute' not in self.queries[extension]:
            return attributes

        query = self.queries[extension]['class_attribute']
        try:
            for pattern_index, capture_dict in query.matches(node):
                # Try different capture names used in various languages
                attr_name_node = capture_dict.get('attribute.name') or capture_dict.get('property.name')
                if attr_name_node:
                    attribute_name = attr_name_node.text.decode('utf8')
                    attributes.append(attribute_name)
        except Exception as e:
            self.log(f"Error extracting class attributes for {extension}: {e}")

        return attributes

    def _extract_parameters(self, node, extension):
        """Extract function parameters."""
        if not node:
            return None

        # Return the raw parameter text for simplicity
        return node.text.decode('utf8').strip()

    def _extract_comments(self, node, extension):
        """Extract comments from a node."""
        comments = []

        if not node or extension not in self.queries or 'comment' not in self.queries[extension]:
            return comments

        query = self.queries[extension]['comment']
        try:
            for pattern_index, capture_dict in query.matches(node):
                comment_node = capture_dict.get('comment')
                if comment_node:
                    comment = comment_node.text.decode('utf8').strip()
                    # Clean up comment markers
                    if comment.startswith('#'):
                        comment = comment[1:].strip()
                    elif comment.startswith('//'):
                        comment = comment[2:].strip()
                    elif comment.startswith('/*') and comment.endswith('*/'):
                        # Handle multi-line block comments better
                        comment = comment[2:-2].strip()
                        comment = '\n'.join(line.strip().lstrip('*').strip() for line in comment.splitlines())
                    comments.append(comment)
        except Exception as e:
            self.log(f"Error extracting comments for {extension}: {e}")

        return comments

    def _extract_imports(self, node, extension):
        """Extract imports from a node."""
        imports = []

        if extension not in self.queries or 'import' not in self.queries[extension]:
            return imports

        query = self.queries[extension]['import']
        try:
            for pattern_index, capture_dict in query.matches(node):
                # Capture the whole import statement for simplicity
                import_node = capture_dict.get('import')
                if import_node:
                    imports.append(import_node.text.decode('utf8').strip())
        except Exception as e:
            self.log(f"Error extracting imports for {extension}: {e}")

        # Remove duplicates and sort
        return sorted(list(set(imports)))

    def _extract_classes(self, node, extension, content):
        """Extract classes from a node."""
        classes = []
        if extension not in self.queries or 'class' not in self.queries[extension]:
            return classes
        query = self.queries[extension]['class']
        try:
            for pattern_index, capture_dict in query.matches(node):
                class_name_node = capture_dict.get('class.name')
                class_body_node = capture_dict.get('class.body')
                class_def_node = capture_dict.get('class.def')  # Get the whole definition node

                if class_name_node and class_def_node:
                    class_name = class_name_node.text.decode('utf8')
                    # --- ADDED LINE NUMBER EXTRACTION ---
                    start_line = class_def_node.start_point[0] + 1  # 0-based row to 1-based line
                    end_line = class_def_node.end_point[0] + 1
                    # --- END ADDED ---

                    class_def = {
                        "name": class_name,
                        "start_line": start_line,  # Store start line
                        "end_line": end_line,  # Store end line
                        "docstring": self._extract_docstring(class_def_node, extension, content),
                        # Check def node for docstring
                        "attributes": self._extract_class_attributes(class_def_node, extension),
                        # Check def node for attributes
                        "methods": []
                    }

                    # Extract methods defined directly within this class body
                    if class_body_node and 'function' in self.queries[extension]:
                        func_query = self.queries[extension]['function']
                        for func_pattern_index, func_capture_dict in func_query.matches(class_body_node):
                            func_name_node = func_capture_dict.get('function.name')
                            func_body_node = func_capture_dict.get('function.body')
                            func_params_node = func_capture_dict.get('function.parameters')
                            method_def_node = func_capture_dict.get(
                                'function.def')  # Get the whole method definition node

                            if func_name_node and method_def_node:
                                method_name = func_name_node.text.decode('utf8')
                                # --- ADDED LINE NUMBER EXTRACTION FOR METHODS ---
                                method_start_line = method_def_node.start_point[0] + 1
                                method_end_line = method_def_node.end_point[0] + 1
                                # --- END ADDED ---

                                method = {
                                    "name": method_name,
                                    "start_line": method_start_line,  # Store start line
                                    "end_line": method_end_line,  # Store end line
                                    "parameters": self._extract_parameters(func_params_node, extension),
                                    "docstring": self._extract_docstring(method_def_node, extension, content),
                                    # Check def node for docstring
                                    "comments": self._extract_comments(method_def_node, extension),
                                    # Check the whole method def
                                    "calls": self._extract_calls(method_def_node, extension),
                                    # Check the whole method def
                                    "raises": self._extract_raises(method_def_node, extension)
                                    # Check the whole method def
                                }
                                class_def["methods"].append(method)

                    classes.append(class_def)
        except Exception as e:
            self.log(f"Error extracting classes for {extension}: {e}\n{traceback.format_exc()}")

        return classes

    def _extract_functions(self, node, extension, content):
        """Extract top-level functions from a node."""
        functions = []

        if extension not in self.queries or 'function' not in self.queries[extension]:
            return functions

        query = self.queries[extension]['function']
        try:
            for pattern_index, capture_dict in query.matches(node):
                func_def_node = capture_dict.get('function.def')
                func_name_node = capture_dict.get('function.name')
                func_body_node = capture_dict.get('function.body')
                func_params_node = capture_dict.get('function.parameters')

                # Skip class methods (basic check, might need refinement for complex cases)
                if func_def_node:
                    parent = func_def_node.parent
                    # Check if parent indicates it's inside a class body (adjust types as needed)
                    if parent and str(parent.type) in ['block', 'class_body', 'declaration_list']:  # Python, Java, TS/JS
                        grandparent = parent.parent
                        if grandparent and str(grandparent.type) in ['class_definition', 'class_declaration']:
                            continue
                    # Specific check for JS/TS method_definition which is always in a class
                    if func_def_node.type == 'method_definition':
                        continue

                # Handle cases like anonymous arrow functions where name might not be captured directly
                function_name = func_name_node.text.decode('utf8') if func_name_node else "[Anonymous Function]"

                if func_def_node:  # Ensure we have the definition node for line numbers
                    # --- ADDED LINE NUMBER EXTRACTION ---
                    start_line = func_def_node.start_point[0] + 1
                    end_line = func_def_node.end_point[0] + 1
                    # --- END ADDED ---

                    function = {
                        "name": function_name,
                        "start_line": start_line,  # Store start line
                        "end_line": end_line,  # Store end line
                        "parameters": self._extract_parameters(func_params_node, extension),
                        "docstring": self._extract_docstring(func_def_node, extension, content),
                        # Check def node for docstring
                        "comments": self._extract_comments(func_def_node, extension),  # Check the whole func def
                        "calls": self._extract_calls(func_def_node, extension),  # Check the whole func def
                        "raises": self._extract_raises(func_def_node, extension)  # Check the whole func def
                    }
                    functions.append(function)
        except Exception as e:
            self.log(f"Error extracting functions for {extension}: {e}\n{traceback.format_exc()}")

        return functions

    def _extract_calls(self, node, extension):
        """Extract function calls from a node."""
        calls = []

        if not node or extension not in self.queries or 'call' not in self.queries[extension]:
            return calls

        query = self.queries[extension]['call']
        try:
            for pattern_index, capture_dict in query.matches(node):
                call_name_node = capture_dict.get('call.name')
                call_object_node = capture_dict.get('call.object')
                call_method_node = capture_dict.get('call.method')

                call_info = {}
                if call_method_node:  # Prioritize object.method calls
                    call_info['method'] = call_method_node.text.decode('utf8')
                    if call_object_node:
                        call_info['object'] = call_object_node.text.decode('utf8')
                    else:
                        call_info['object'] = '[Unknown Object]'  # Placeholder if object capture fails
                elif call_name_node:
                    call_info['name'] = call_name_node.text.decode('utf8')

                if call_info and call_info not in calls:  # Avoid duplicates
                    calls.append(call_info)
        except Exception as e:
            self.log(f"Error extracting calls for {extension}: {e}")

        return calls

    def _extract_raises(self, node, extension):
        """Extract raised exceptions from a node."""
        raises = []

        if not node or extension not in self.queries or 'raise' not in self.queries[extension]:
            return raises

        query = self.queries[extension]['raise']
        try:
            for pattern_index, capture_dict in query.matches(node):
                raise_node = capture_dict.get('raise')
                if raise_node:
                    # Get the exception being raised (often the first child after 'raise'/'throw')
                    exception_text = raise_node.text.decode('utf8').strip()
                    # Basic cleanup
                    if exception_text.startswith('raise '):
                        exception_text = exception_text[len('raise '):].strip()
                    elif exception_text.startswith('throw '):
                        exception_text = exception_text[len('throw '):].strip()
                    # Remove trailing semicolon for Java/JS/TS
                    if exception_text.endswith(';'):
                        exception_text = exception_text[:-1].strip()

                    if exception_text not in raises:
                        raises.append(exception_text)
        except Exception as e:
            self.log(f"Error extracting raises for {extension}: {e}")

        return raises

    def _extract_docstring(self, node, extension, content):
        """Extract docstring from a node."""
        if not node or extension not in self.queries or 'docstring' not in self.queries[extension]:
            return None

        query = self.queries[extension]['docstring']
        try:
            # Match against the specific node provided (e.g., class_def, func_def)
            # The query itself might specify which node type it expects
            # We may need to adjust how matches are retrieved if the query targets children
            matches = query.matches(node)

            # Find the docstring capture within the matches *related* to the input node
            for pattern_index, capture_dict in matches:
                docstring_node = capture_dict.get('docstring')
                parent_capture_node = capture_dict.get('function_with_docstring') or capture_dict.get(
                    'class_with_docstring')

                # Ensure the matched docstring belongs to the node we are analyzing
                if docstring_node and parent_capture_node and parent_capture_node.id == node.id:
                    docstring = docstring_node.text.decode('utf8')
                    # Clean up docstring quotes and potential language artifacts
                    if docstring.startswith('"""') and docstring.endswith('"""'):
                        docstring = docstring[3:-3]
                    elif docstring.startswith("'''") and docstring.endswith("'''"):
                        docstring = docstring[3:-3]
                    elif docstring.startswith('"') and docstring.endswith('"'):
                        docstring = docstring[1:-1]
                    elif docstring.startswith("'") and docstring.endswith("'"):
                        docstring = docstring[1:-1]
                    # Handle JavaDoc style comments if captured
                    elif docstring.startswith('/*') and docstring.endswith('*/'):
                        docstring = docstring[2:-2]  # Remove delimiters
                        # Basic cleanup for JavaDoc * prefixes
                        lines = docstring.splitlines()
                        cleaned_lines = []
                        for line in lines:
                            stripped_line = line.strip()
                            if stripped_line.startswith('*'):
                                cleaned_lines.append(stripped_line[1:].strip())
                            else:
                                cleaned_lines.append(stripped_line)
                        docstring = "\n".join(filter(None, cleaned_lines)).strip()  # Remove empty lines

                    return docstring.replace('\\n', '\n').replace('\\"', '"').strip()
        except Exception as e:
            self.log(f"Error extracting docstring for {extension}: {e}")

        return None

    def generate_ucl_from_local(self, local_dir, output_file=None):
        """Generate a UCL file from a local directory."""
        # Validate directory
        if not os.path.isdir(local_dir):
            raise ValueError(f"Directory '{local_dir}' does not exist or is not a directory")

        self.log(f"Analyzing local directory: {local_dir}")
        return self._process_codebase(local_dir, output_file)

    def handle_remove_error(self, func, path, exc_info):
        """Error handler for shutil.rmtree to deal with potential read-only files."""
        # Check if the error is due to permissions
        # Note: Error codes might vary slightly across OS, but EACCES/PermissionError is common
        if isinstance(exc_info[1], PermissionError) or (hasattr(os, 'EACCES') and exc_info[1].errno == os.EACCES):
            try:
                # Try changing permissions and retrying deletion
                if os.access(path, os.W_OK):  # Already writable, maybe different issue?
                    raise  # Reraise original error if already writable
                os.chmod(path, stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)  # Add write permissions
                func(path)  # Retry the function (e.g., os.remove, os.rmdir)
            except Exception as e:
                self.log(f"Retrying removal failed for {path}: {e}")
                raise  # Reraise if retry also fails
        else:
            # If it's not a permission error, raise the original error
            self.log(f"Non-permission error during cleanup {path}: {exc_info[1]}")
            raise exc_info[1]

    def generate_ucl_from_github(self, repo_url, output_file=None):
        """Generate a UCL file from a GitHub repository."""
        temp_dir = None  # Initialize to None
        try:
            # Clone repository
            temp_dir = self.clone_repository(repo_url)
            self.log(f"Processing cloned repository: {temp_dir}")
            ucl_output = self._process_codebase(temp_dir, output_file)
            return ucl_output
        except Exception as e:
            self.log(f"Error during GitHub processing: {e}")
            raise  # Reraise the exception after logging
        finally:
            # Ensure cleanup temporary directory happens even if errors occur
            if temp_dir and os.path.exists(temp_dir):
                self.log(f"Cleaning up temporary directory: {temp_dir}")
                try:
                    shutil.rmtree(temp_dir, onerror=self.handle_remove_error)
                except Exception as cleanup_error:
                    self.log(f"Error cleaning up temporary directory {temp_dir}: {cleanup_error}")

    def _process_codebase(self, repo_dir, output_file=None):
        """Process a codebase directory and generate UCL output."""
        # Get file structure
        file_structure = self.get_file_structure(repo_dir)
        self.log(f"Found {len(file_structure)} files to analyze")

        # Build tree structure from file paths
        tree = self.build_tree(file_structure)

        # Generate UCL content with file structure
        ucl_content = ["# File Structure"]
        ucl_content.extend(self.print_tree(tree))
        ucl_content.append("\n# UCL Representation")

        # Process each file
        for i, relative_file_path in enumerate(file_structure):
            self.log(f"Processing file {i + 1}/{len(file_structure)}: {relative_file_path}")
            full_path = Path(repo_dir) / relative_file_path  # Use Pathlib for joining
            extension = full_path.suffix  # Get extension using Pathlib

            # Skip unsupported file types based on LANGUAGE_MAP keys
            if extension not in self.LANGUAGE_MAP:
                self.log(f"Skipping unsupported file type: {relative_file_path}")
                continue

            # Also skip if parser wasn't initialized (e.g., due to error)
            if extension not in self.parsers:
                self.log(f"Skipping file due to missing parser: {relative_file_path}")
                continue

            file_ucl = []
            file_ucl.append(f"\n--- {relative_file_path} ---")  # Use relative path for consistency

            parse_result = self.parse_file(full_path)
            # self.log(f"Parse result for {relative_file_path}: {parse_result}") # Debug log

            # Handle parsing errors
            if "error" in parse_result:
                file_ucl.append(f"ERROR parsing file: {parse_result['error']}")
                ucl_content.extend(file_ucl)
                continue
            elif "message" in parse_result:  # Handle "not supported" message
                file_ucl.append(f"INFO: {parse_result['message']}")
                ucl_content.extend(file_ucl)
                continue

            # Add imports
            if parse_result.get("imports"):
                file_ucl.append("Imports:")
                for imp in parse_result["imports"]:
                    file_ucl.append(f"    - {imp}")

            # Add top-level functions
            for func in parse_result.get("functions", []):
                # --- UPDATED FORMATTING ---
                file_ucl.append(f"Function: {func['name']} (Lines {func['start_line']}-{func['end_line']})")
                # --- END UPDATED ---

                # Add parameters
                if func.get("parameters") is not None:  # Check explicitly for None
                    file_ucl.append(f"    - Parameters: {func['parameters']}")

                # Add function docstring
                if func.get("docstring"):
                    docstring = func["docstring"].replace("\n", "\n        ")  # Indent subsequent lines
                    file_ucl.append(f"    - Docstring: \"\"\"{docstring}\"\"\"")

                # Add comments
                if func.get("comments"):
                    file_ucl.append("    - Comments:")
                    for comment in func["comments"]:
                        # Indent multi-line comments correctly
                        indented_comment = comment.replace("\n", "\n            ")
                        file_ucl.append(f"        - {indented_comment}")

                # Add function calls
                if func.get("calls"):
                    file_ucl.append("    - Calls:")
                    for call in func["calls"]:
                        if 'object' in call and 'method' in call:
                            file_ucl.append(f"        - {call['object']}.{call['method']}()")
                        elif 'name' in call:
                            file_ucl.append(f"        - {call['name']}()")

                # Add function raises
                if func.get("raises"):
                    file_ucl.append("    - Raises:")
                    for raise_stmt in func["raises"]:
                        file_ucl.append(f"        - {raise_stmt}")

            # Add classes
            for cls in parse_result.get("classes", []):
                # --- UPDATED FORMATTING ---
                file_ucl.append(f"Class: {cls['name']} (Lines {cls['start_line']}-{cls['end_line']})")
                # --- END UPDATED ---

                # Add class docstring
                if cls.get("docstring"):
                    docstring = cls["docstring"].replace("\n", "\n        ")  # Indent subsequent lines
                    file_ucl.append(f"    - Docstring: \"\"\"{docstring}\"\"\"")

                # Add class attributes
                if cls.get("attributes"):
                    file_ucl.append("    - Attributes:")
                    for attr in cls["attributes"]:
                        file_ucl.append(f"        - {attr}")

                # Add methods
                if cls.get("methods"):
                    file_ucl.append("    - Methods:")
                    for method in cls["methods"]:
                        # --- UPDATED FORMATTING ---
                        file_ucl.append(
                            f"        - {method['name']} (Lines {method['start_line']}-{method['end_line']})")
                        # --- END UPDATED ---

                        # Add parameters
                        if method.get("parameters") is not None:  # Check explicitly for None
                            file_ucl.append(f"            - Parameters: {method['parameters']}")

                        # Add method docstring
                        if method.get("docstring"):
                            docstring = method["docstring"].replace("\n", "\n                ")  # Indent further
                            file_ucl.append(f"            - Docstring: \"\"\"{docstring}\"\"\"")

                        # Add comments within the method
                        if method.get("comments"):
                            file_ucl.append("            - Comments:")
                            for comment in method["comments"]:
                                # Indent multi-line comments correctly
                                indented_comment = comment.replace("\n", "\n                ")
                                file_ucl.append(f"                - {indented_comment}")

                        # Add method calls within the method
                        if method.get("calls"):
                            file_ucl.append("            - Calls:")
                            for call in method["calls"]:
                                if 'object' in call and 'method' in call:
                                    file_ucl.append(f"                - {call['object']}.{call['method']}()")
                                elif 'name' in call:
                                    file_ucl.append(f"                - {call['name']}()")

                        # Add method raises within the method
                        if method.get("raises"):
                            file_ucl.append("            - Raises:")
                            for raise_stmt in method["raises"]:
                                file_ucl.append(f"                - {raise_stmt}")

            # Only add the file section if there was something extracted beyond the header
            if len(file_ucl) > 1:
                ucl_content.extend(file_ucl)
            else:
                # Optionally log files that had nothing interesting extracted
                # self.log(f"No significant UCL content found for {relative_file_path}")
                pass

        # Join all lines
        ucl_output = "\n".join(ucl_content)

        # Write to file if requested
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(ucl_output)
                self.log(f"UCL file written to {output_file}")
            except Exception as e:
                self.log(f"Error writing output file {output_file}: {e}")
                # Decide if you want to raise the error or just log it
                # raise e

        return ucl_output
