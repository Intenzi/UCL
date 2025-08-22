# codebase_manager.py
import os
import tempfile
import shutil
from pathlib import Path
import logging

# Assuming ucl_generator.py contains the UCLGenerator class
# with the added generate_structured_ucl_... methods
from ucl import UCLGenerator

# Configure basic logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class CodebaseIndexManager:
    """
    Manages the loading and accessing of codebase UCL data.
    Acts as a stateful component for the stateless MCP handlers.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        # Make it a Singleton
        if cls._instance is None:
            cls._instance = super(CodebaseIndexManager, cls).__new__(cls)
            # Initialize instance attributes only once
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.generator = UCLGenerator(logger=log.info) # Use logger
        self.codebase_root: Path | None = None
        self.ucl_data: dict | None = None
        self._temp_dir_path: Path | None = None # For GitHub clones
        self._initialized = True
        log.info("CodebaseIndexManager initialized.")

    def _cleanup_previous(self):
        """Cleans up temporary directory from previous GitHub clone if any."""
        if self._temp_dir_path and self._temp_dir_path.exists():
            log.info(f"Cleaning up previous temporary directory: {self._temp_dir_path}")
            try:
                shutil.rmtree(self._temp_dir_path, onerror=self.generator.handle_remove_error)
            except Exception as e:
                log.error(f"Error during cleanup of {self._temp_dir_path}: {e}", exc_info=True)
            finally:
                 self._temp_dir_path = None # Ensure it's cleared even if rmtree fails partially

        # Clear existing data when loading new codebase
        self.codebase_root = None
        self.ucl_data = None


    async def index_local_codebase(self, path: str) -> tuple[bool, str]:
        """Loads and processes a local codebase."""
        self._cleanup_previous()
        log.info(f"Attempting to index local codebase at: {path}")
        try:
            local_path = Path(path).resolve()
            if not local_path.is_dir():
                msg = f"Path is not a valid directory: {local_path}"
                log.error(msg)
                return False, msg

            # Use the NEW structured method
            ucl_structure = self.generator.generate_structured_ucl_from_local(str(local_path))
            self.ucl_data = ucl_structure
            self.codebase_root = local_path # Store the resolved Path object
            msg = f"Successfully indexed local codebase: {self.codebase_root}"
            log.info(msg)
            return True, msg
        except Exception as e:
            log.error(f"Failed to index local codebase '{path}': {e}", exc_info=True)
            self.codebase_root = None
            self.ucl_data = None
            return False, f"Error indexing local codebase: {e}"

    async def index_github_codebase(self, url: str) -> tuple[bool, str]:
        """Clones and processes a GitHub repository."""
        self._cleanup_previous()
        log.info(f"Attempting to index GitHub repository: {url}")
        try:
            # Clone to a new temporary directory each time
            temp_dir = tempfile.mkdtemp()
            self._temp_dir_path = Path(temp_dir) # Track for cleanup

            # Use the NEW structured method
            ucl_structure, repo_clone_path_str = self.generator.generate_structured_ucl_from_github(
                url,
                clone_dir=temp_dir # Explicitly use the temp dir we created
            )
            self.ucl_data = ucl_structure
            self.codebase_root = Path(repo_clone_path_str) # Store Path obj
            msg = f"Successfully cloned and indexed GitHub repo to: {self.codebase_root}"
            log.info(msg)
            return True, msg
        except Exception as e:
            log.error(f"Failed to index GitHub repo '{url}': {e}", exc_info=True)
            self.codebase_root = None
            self.ucl_data = None
            self._cleanup_previous() # Clean up the failed clone attempt
            return False, f"Error indexing GitHub repo: {e}"

    def get_ucl_data(self) -> dict | None:
        """Returns the loaded UCL data."""
        return self.ucl_data

    def get_codebase_root(self) -> Path | None:
        """Returns the root path of the loaded codebase."""
        return self.codebase_root

    def get_file_source_lines(self, relative_file_path: str, start_line: int | None = None, end_line: int | None = None) -> tuple[str | None, str]:
        """
        Gets lines from the source file (not the UCL representation).
        Returns (content, status_message)
        """
        if not self.codebase_root:
            return None, "Error: No codebase is currently indexed."

        full_path = self.codebase_root / relative_file_path
        log.debug(f"Attempting to read lines from: {full_path}")

        if not full_path.is_file():
            # Try normalizing just in case? Be careful with case sensitivity.
            normalized_path_str = str(relative_file_path).replace("\\", "/")
            full_path = self.codebase_root / normalized_path_str
            if not full_path.is_file():
                log.error(f"Source file not found at: {full_path}")
                return None, f"Error: Source file not found: {relative_file_path}"

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if start_line is None and end_line is None:
                return "".join(lines), "Success: Returned full file content."

            start_index = max(0, start_line - 1) if start_line is not None else 0
            end_index = end_line if end_line is not None else len(lines)

            if start_index >= len(lines):
                msg = f"Warning: Start line {start_line} is beyond file end ({len(lines)} lines)."
                log.warning(msg)
                return "", msg
            if end_index < start_index:
                 msg = f"Warning: End line {end_line} is before start line {start_line}."
                 log.warning(msg)
                 return "", msg

            selected_lines = lines[start_index:end_index]
            return "".join(selected_lines), f"Success: Returned lines {start_line or 1}-{end_line or len(lines)}."

        except Exception as e:
            msg = f"Error reading file '{full_path}': {e}"
            log.error(msg, exc_info=True)
            return None, msg

    def get_parsed_file_ucl(self, relative_file_path: str) -> dict | None:
        """Gets the parsed UCL dictionary for a specific file."""
        if not self.ucl_data or 'parsed_files' not in self.ucl_data:
            return None
        # Ensure keys are consistently using forward slashes
        normalized_path = relative_file_path.replace(os.sep, '/')
        return self.ucl_data['parsed_files'].get(normalized_path)

    def get_file_tree(self) -> dict | None:
         """Gets the file tree structure."""
         if not self.ucl_data:
              return None
         return self.ucl_data.get('file_tree')

    def get_parsed_files_list(self) -> list[str] | None:
        """Gets a list of relative paths for all parsed files."""
        if not self.ucl_data or 'parsed_files' not in self.ucl_data:
             return None
        return list(self.ucl_data['parsed_files'].keys())


# Create a single instance of the manager for the server to use
manager = CodebaseIndexManager()