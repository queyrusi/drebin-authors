import staticAnalyzer
import sys
import shutil
import os

# Path to the directory you want to remove
dir_path = 'working_dir/'

# Check if the directory exists
if os.path.exists(dir_path) and os.path.isdir(dir_path):
    # Remove the directory and all its contents
    shutil.rmtree(dir_path)
    print(f"Directory '{dir_path}' has been removed.")
else:
    print(f"Directory '{dir_path}' does not exist.")

staticAnalyzer.run(sys.argv[1], sys.argv[2])
