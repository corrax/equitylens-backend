import os
import json
import boto3
import subprocess
import tempfile
import base64
import shutil
from pathlib import Path
from botocore.client import Config
from requests_toolbelt.multipart import decoder
import datetime
import time

BUCKET = os.environ.get('BUCKET_NAME')
RL_TABLE = os.environ.get('RATE_LIMITS_TABLE')
RL_IP_LIMIT = int(os.environ.get('RATE_LIMIT_IP_DAILY', 50))

s3 = boto3.client('s3', config=Config(signature_version='s3v4'))
ddb = boto3.resource('dynamodb')

SOFFICE_PATH = "/opt/libreoffice7.6/program/soffice"

def get_ip(event):
    return event.get('requestContext', {}).get('identity', {}).get('sourceIp') or \
           event.get('requestContext', {}).get('http', {}).get('sourceIp') or \
           (event.get('headers', {}).get('x-forwarded-for', '').split(',')[0].strip()) or \
           '0.0.0.0'

def rate_limit_check(event, cost=1):
    if not RL_TABLE:
        return {'ok': True}
    
    day = datetime.datetime.utcnow().strftime('%Y%m%d')
    ip = get_ip(event)
    now = int(time.time())
    ttl = now + 86400  # TTL midnight+1 day

    if RL_IP_LIMIT <= 0:
        return {'ok': True}

    table = ddb.Table(RL_TABLE)
    key = f"ip:{ip}:{day}"

    try:
        res = table.update_item(
            Key={'k': key},
            UpdateExpression='SET cnt = if_not_exists(cnt, :z) + :inc, expiresAt = if_not_exists(expiresAt, :ttl)',
            ExpressionAttributeValues={':z': 0, ':inc': cost, ':ttl': ttl},
            ReturnValues='UPDATED_NEW'
        )
        count = int(res.get('Attributes', {}).get('cnt', 0))
        if count > RL_IP_LIMIT:
            return {'ok': False, 'scope': 'ip', 'limit': RL_IP_LIMIT, 'count': count}
    except Exception as e:
        print(f"Rate limit check failed: {e}")
        # Fail open
        return {'ok': True}

    return {'ok': True}

def response(statusCode, body, headers={}):
  final_headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': '*',
  }
  final_headers.update(headers)
  return {
    'statusCode': statusCode,
    'headers': final_headers,
    'body': json.dumps(body)
  }

def handler(event, context):
  if not os.path.exists(SOFFICE_PATH):
    return response(501, {'message': 'LibreOffice is not installed in the container'})

  rl = rate_limit_check(event)
  if not rl.get('ok'):
    return response(429, {'message': 'Rate limit exceeded', 'scope': rl.get('scope'), 'limit': rl.get('limit'), 'count': rl.get('count')})

  try:
    content_type = event['headers'].get('content-type') or event['headers'].get('Content-Type')
    if not content_type:
      return response(400, {'message': 'Missing Content-Type header'})

    # Guard: multipart should come base64-encoded via API Gateway binary media types
    if 'multipart/form-data' in content_type.lower() and not event.get('isBase64Encoded', False):
      return response(415, {'message': 'multipart/form-data arrived non-base64 (API Gateway BinaryMediaTypes not set).'})

    body_str = event.get('body', '')
    if event.get('isBase64Encoded', False):
      body_bytes = base64.b64decode(body_str)
    else:
      # Use latin1 to preserve raw bytes 1:1 if API already passed bytes
      body_bytes = body_str.encode('latin1')

    multipart_data = decoder.MultipartDecoder(body_bytes, content_type)

    file_content, filename = None, 'upload'
    for part in multipart_data.parts:
      disp = part.headers.get(b'Content-Disposition', b'').decode()
      if 'name="file"' in disp:
        file_content = part.content
        # safer filename extraction
        fn = disp.split('filename=')[-1].strip().strip('"').split(';')[0]
        from re import sub
        filename = sub(r'[^A-Za-z0-9._-]+', '_', Path(fn).name) or 'upload'
        break
    if not file_content:
      return response(400, {'message': 'File part missing in multipart form'})

    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      in_path = tmp_path / filename
      with open(in_path, 'wb') as f:
        f.write(file_content)

      out_dir = tmp_path / 'out'
      out_dir.mkdir(parents=True, exist_ok=True)

      # Call the actual soffice binary; extra flags removed
      cp = subprocess.run(
        [SOFFICE_PATH, '--headless', '--nologo', '--norestore',
         '--convert-to', 'pdf:writer_pdf_Export', '--outdir', str(out_dir), str(in_path)],
        check=False, capture_output=True, text=True
      )
      if cp.returncode != 0:
        return response(500, {'message': 'Conversion failed', 'stderr': cp.stderr.strip()})

      pdf_path = out_dir / (in_path.stem + '.pdf')
      if not pdf_path.exists():
        return response(500, {'message': 'Conversion failed: PDF not produced'})

      with open(pdf_path, 'rb') as f:
        pdf_b64 = base64.b64encode(f.read()).decode('utf-8')
      return response(200, {'pdf': pdf_b64})

  except Exception as e:
    return response(500, {'message': 'Internal server error', 'detail': str(e)})
