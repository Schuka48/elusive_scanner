import gzip

script_code = open('misc/script.py', 'rt').read()

compressed_data = gzip.compress(script_code.encode('utf-8'))
print(compressed_data)
with open('misc/compress.gz', 'wb') as archive:
    archive.write(compressed_data)
print(gzip.decompress(compressed_data))
