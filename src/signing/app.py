import os
import io
import json
import boto3
from datetime import datetime
from botocore.client import Config

TABLE = os.environ.get('TABLE_NAME')
BUCKET = os.environ.get('BUCKET_NAME')
SIGNER_PFX_S3_KEY = os.environ.get('SIGNER_PFX_S3_KEY')
SIGNER_PFX_PASSWORD = os.environ.get('SIGNER_PFX_PASSWORD', '')
TSA_URL = os.environ.get('TSA_URL')

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TABLE) if TABLE else None
s3 = boto3.client('s3', config=Config(signature_version='s3v4'))

def handler(event, context):
    body = event if isinstance(event, dict) else json.loads(event or '{}')
    session_id = body.get('sessionId')
    key = body.get('key')
    if not session_id or not key:
        return { 'statusCode': 400, 'body': json.dumps({'message': 'Missing sessionId or key'}) }

    key_signed = f"{session_id}/signed.pdf"

    # Get session details from DynamoDB
    if table is None:
        return { 'statusCode': 500, 'body': json.dumps({'message': 'DynamoDB table not configured'}) }
    
    session_item = table.get_item(Key={'sessionId': session_id}).get('Item', {})
    fields = session_item.get('fields', [])
    signers_map = {s['id']: s for s in session_item.get('signers', [])}

    # Download input PDF
    src_obj = s3.get_object(Bucket=BUCKET, Key=key)
    pdf_bytes = src_obj['Body'].read()

    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers
        from pyhanko.sign.fields import SigFieldSpec
        from pyhanko.sign.timestamps import HTTPTimeStamper
        from pyhanko.sign.general import SigningError
        from pyhanko.pdf_utils.font import opentype
        from pyhanko.sign.appearance import SignatureAppearance, TextLabel
        from io import BytesIO

        # Load PKCS#12 signer credentials from S3 (required)
        if not SIGNER_PFX_S3_KEY:
            raise RuntimeError('SIGNER_PFX_S3_KEY is not set')
        cred_obj = s3.get_object(Bucket=BUCKET, Key=SIGNER_PFX_S3_KEY)
        pfx_data = cred_obj['Body'].read()
        signer = signers.SimpleSigner.load_pkcs12(pfx_data, SIGNER_PFX_PASSWORD.encode('utf-8'))
        
        timestamper = HTTPTimeStamper(TSA_URL) if TSA_URL else None
        
        pdf_out = BytesIO()
        w = IncrementalPdfFileWriter(BytesIO(pdf_bytes))

        for field in fields:
            signer_info = signers_map.get(field['signerId'], {})
            field_name = f"Signature-{field['id']}"
            
            # Create a custom appearance
            # Note: Assumes a font is available. For Lambda, package a font file.
            # For simplicity, we'll rely on pyHanko's default font handling.
            dt_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
            
            appearance = SignatureAppearance(
                fill_rect=(0, 0, field['w'], field['h']),
                background_text=[
                    TextLabel(
                        text=f"Signed by: {signer_info.get('name', '')}",
                        font_size=8,
                        x=5, y=field['h'] - 10
                    ),
                    TextLabel(
                        text=signer_info.get('email', ''),
                        font_size=7,
                        x=5, y=field['h'] - 20
                    ),
                    TextLabel(
                        text=f"Signed on: {dt_str}",
                        font_size=7,
                        x=5, y=5
                    )
                ]
            )

            signers.sign_pdf(
                w,
                SigFieldSpec(
                    sig_field_name=field_name,
                    box=(field['x'], field['y'], field['x'] + field['w'], field['y'] + field['h']),
                    on_page=field['page']
                ),
                signer=signer,
                timestamper=timestamper,
                appearance=appearance
            )

        w.write(pdf_out)
        out_bytes = pdf_out.getvalue()

        s3.put_object(Bucket=BUCKET, Key=key_signed, Body=out_bytes, ContentType='application/pdf')
        status = 'SIGNED'
    except Exception as e:
        print(f'Signing failed: {e}')
        # Fallback to copy
        s3.copy_object(Bucket=BUCKET, CopySource={'Bucket': BUCKET, 'Key': key}, Key=key_signed)
        status = 'SIGNING_FAILED'

    table.update_item(
        Key={'sessionId': session_id},
        UpdateExpression='SET #st = :s, keySigned = :k, updatedAt = :u',
        ExpressionAttributeNames={'#st': 'status'},
        ExpressionAttributeValues={':s': status, ':k': key_signed, ':u': datetime.utcnow().isoformat()}
    )

    return { 'statusCode': 200, 'body': json.dumps({'ok': True, 'keySigned': key_signed}) }
