python -m venv .venv
source .venv/Scripts/activate
pip install -e .
patchmgr --version
cd docker-test/ubuntu
./scripts/stop.sh
./scripts/build.sh
./scripts/run.sh
 
./scripts/test-scan.sh                       # sanity check root login
./scripts/test-patch.sh --no-dry-run         # actually install patches