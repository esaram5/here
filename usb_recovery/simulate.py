"""Explicit offline protocol state machine. No USB or process interaction."""
from pathlib import Path
from .analyze import write_json

class Simulator:
    def __init__(self, config):
        self.state = config['initial_state']
        self.rules = config['rules']
        self.saved = bytearray()
        for r in self.rules:
            expected = bytes.fromhex(r['expect_hex'])
            mask = bytes.fromhex(r.get('mask_hex', 'ff' * len(expected)))
            if len(mask) != len(expected):
                raise ValueError('Mask length mismatch')
            response = bytes.fromhex(r.get('response_hex', ''))
            if not isinstance(r['state'], str) or not isinstance(r['next_state'], str):
                raise ValueError('State names must be strings')
            if 'save_range' in r:
                self.check_range(r['save_range'], len(expected))
            for echo in r.get('echo', []):
                self.check_range(echo['request_range'], len(expected))
                a,b = echo['request_range']; at = echo['response_offset']
                if not isinstance(at,int) or not 0 <= at <= len(response) - (b-a):
                    raise ValueError('Echo outside response')

    @staticmethod
    def check_range(value, size):
        if len(value) != 2 or any(not isinstance(x,int) for x in value) or not 0 <= value[0] <= value[1] <= size:
            raise ValueError('Invalid byte range')

    def step(self, request):
        matches = []
        for r in self.rules:
            expected = bytes.fromhex(r['expect_hex'])
            mask = bytes.fromhex(r.get('mask_hex','ff'*len(expected)))
            if self.state == r['state'] and len(request) == len(expected) and all(a&m == b&m for a,b,m in zip(request,expected,mask)):
                matches.append(r)
        if len(matches) != 1:
            raise ValueError(f'State {self.state}: {len(matches)} matching rules; no default success response')
        r = matches[0]
        response = bytearray(bytes.fromhex(r.get('response_hex','')))
        for echo in r.get('echo',[]):
            a,b = echo['request_range']; at = echo['response_offset']
            response[at:at+b-a] = request[a:b]
        if 'save_range' in r:
            a,b = r['save_range']; self.saved.extend(request[a:b])
        before = self.state; self.state = r['next_state']
        return dict(state_before=before, state_after=self.state, rule=r.get('name',''),request_hex=request.hex(),response_hex=response.hex())

def simulate(config, requests, output):
    machine = Simulator(config)
    transcript = [machine.step(bytes.fromhex(x)) for x in requests]
    if config.get('final_state') is not None and machine.state != config['final_state']:
        raise ValueError('Incomplete session: final state not reached')
    out = Path(output); out.mkdir(parents=True, exist_ok=False)
    write_json(out/'transcript.json', dict(offline_only=True, final_state=machine.state, steps=transcript))
    (out/'saved_payload.bin').write_bytes(machine.saved)
    return machine.state
