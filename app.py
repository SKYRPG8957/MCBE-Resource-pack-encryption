import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from flask import Flask, render_template, request, send_file, after_this_request, jsonify
from encrypt import encrypt_pack, EncryptOptions, ensure_pycryptodome, random_key

app = Flask(__name__, 
            static_url_path='/static', 
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'),
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB limit

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith('.zip'):
        return jsonify({'error': 'Only ZIP files are allowed'}), 400

    # Options
    exclude_manifest = request.form.get('exclude_manifest') == 'true'
    exclude_pack_icon = request.form.get('exclude_pack_icon') == 'true'
    exclude_bug_icon = request.form.get('exclude_bug_icon') == 'true'

    # Create distinct temp dir for this request
    temp_dir = Path(tempfile.mkdtemp())
    
    try:
        # Save uploaded file
        input_zip_path = temp_dir / "input.zip"
        file.save(input_zip_path)

        # Output paths
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        
        output_zip_name = Path(file.filename).stem + "_encrypted.zip"
        output_zip_path = output_dir / output_zip_name
        
        key_file_name = Path(file.filename).stem + ".zip.key"
        key_file_path = output_dir / key_file_name

        excluded = set()
        if exclude_manifest: excluded.add("manifest.json")
        if exclude_pack_icon: excluded.add("pack_icon.png")
        if exclude_bug_icon: excluded.add("bug_pack_icon.png")

        opts = EncryptOptions(
            input_zip=input_zip_path,
            output_dir=output_dir,
            output_zip=output_zip_path,
            key_file=key_file_path,
            master_key=random_key(),
            excluded_files=excluded
        )

        # Ensure dependencies (just in case)
        if not ensure_pycryptodome():
            return jsonify({'error': 'Server configuration error: PyCryptodome missing'}), 500

        # Run encryption
        # We can pass simple log/progress callbacks if we want, or ignore them
        encrypt_pack(opts)

        # Zip the result (encrypted zip + key file + info txt)
        # To make it easy for the user, we'll zip everything in the output folder into one download
        # OR we could just send the zip if the key is inside? The key is usually outside.
        # Let's create a wrapper zip containing both.
        
        final_download_name = Path(file.filename).stem + "_result.zip"
        final_download_path = temp_dir / final_download_name
        
        with zipfile.ZipFile(final_download_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item in output_dir.glob('*'):
                zf.write(item, arcname=item.name)

        @after_this_request
        def cleanup(response):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"Error cleaning up temp dir: {e}")
            return response

        return send_file(final_download_path, as_attachment=True, download_name=final_download_name)

    except Exception as e:
        shutil.rmtree(temp_dir)
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Flask server...")
    print("Please make sure 'flask' is installed: pip install flask")
    app.run(debug=True, port=5000)
