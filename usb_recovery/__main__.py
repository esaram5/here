import argparse
import json
from pathlib import Path
import sys
import zipfile
from .analyze import analyze, bounded_read
from .simulate import simulate

def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline USB recovery tools; no device writes')
    sub = parser.add_subparsers(dest='command', required=True)
    a = sub.add_parser('analyze', help='Analyze result ZIP/folder, PCAP or PCAPNG')
    a.add_argument('source'); a.add_argument('--out', required=True)
    a.add_argument('--bus', type=int); a.add_argument('--device', type=int)
    a.add_argument('--compare'); a.add_argument('--input-file')
    a.add_argument('--marker', type=float, help='Message seconds after first selected USB frame')
    s = sub.add_parser('simulate', help='Offline replay of explicit JSON rules')
    s.add_argument('rules'); s.add_argument('requests'); s.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'analyze':
            if args.marker is not None and args.marker < 0: parser.error('--marker must be nonnegative')
            r = analyze(args.source,args.out,args.bus,args.device,args.compare,args.input_file,args.marker)
            print(f"Report: {Path(args.out)/'report.md'} ({r['usb_frames']} USB frames)")
        else:
            load = lambda p: json.loads(bounded_read(p,4*1024*1024).decode('utf-8-sig'))
            state = simulate(load(args.rules),load(args.requests),args.out)
            print(f'Offline simulation finished in state {state}: {args.out}')
        return 0
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e:
        print(f'ERROR: {e}',file=sys.stderr); return 2

if __name__ == '__main__': sys.exit(main())
