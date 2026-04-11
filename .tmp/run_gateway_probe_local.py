import sys
sys.path.insert(0, r'C:\Users\andyw\Desktop\prompt_injection_fuzzing_third\src')
from pi_fuzzer.gateway_probe_runtime import run_gateway_probe_server
run_gateway_probe_server(host='127.0.0.1', port=8012, litellm_base_url='http://127.0.0.1:4000')
