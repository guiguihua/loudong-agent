Set-Location 'E:\damoxingdaima\loudong-agent'
$env:PYTHONPATH=(Resolve-Path 'src').Path
python -m uvicorn vuln_agent.api:create_app --factory --host 127.0.0.1 --port 8001 *> .data\service-8001-live.log
