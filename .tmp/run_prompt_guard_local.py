import sys
sys.path.insert(0, r'C:\Users\andyw\Desktop\prompt_injection_fuzzing_third\src')
from pi_fuzzer.prompt_guard_runtime import run_prompt_guard_server
run_prompt_guard_server(host='127.0.0.1', port=8011, use_mock=True)
