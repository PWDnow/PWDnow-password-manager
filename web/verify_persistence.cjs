const { createHash, randomBytes, createCipheriv, createDecipheriv } = require('crypto');

const BASE_URL = 'http://127.0.0.1:1234';

async function run() {
  console.log('1. Logging in...');
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'wang@gmail.com', password: 'name' })
  });
  const loginData = await loginRes.json();
  const cookie = loginRes.headers.get('set-cookie');
  const csrf = cookie.match(/_pwd_csrf=([^;]+)/)[1];
  console.log('Login OK. CSRF:', csrf);

  // Simulate folder creation
  console.log('2. Creating folder...');
  const folderData = JSON.stringify([{ id: 'test-folder-id', label: 'Test Folder' }]);
  // Note: we don't have the client-side key to do proper encryption, 
  // but the server doesn't care. It just stores the blob.
  const encryptedBlob = 'FAKE_ENCRYPTED_BLOB_' + Date.now();

  const putRes = await fetch(`${BASE_URL}/api/vault/folders`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
      'Cookie': cookie
    },
    body: JSON.stringify({ data: encryptedBlob })
  });
  console.log('PUT Folders status:', putRes.status);

  console.log('3. Verifying persistence...');
  const getRes = await fetch(`${BASE_URL}/api/vault/folders`, {
    headers: { 'Cookie': cookie }
  });
  const getData = await getRes.json();
  console.log('Server returned:', JSON.stringify(getData));

  if (getData.data === encryptedBlob) {
    console.log('SUCCESS: Data persisted during session.');
  } else {
    console.error('FAILURE: Data mismatch during session!');
  }

  // RE-LOGIN (Simulate refresh/logout)
  console.log('4. Re-logging in...');
  const loginRes2 = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'wang@gmail.com', password: 'name' })
  });
  const cookie2 = loginRes2.headers.get('set-cookie');
  
  const getRes2 = await fetch(`${BASE_URL}/api/vault/folders`, {
    headers: { 'Cookie': cookie2 }
  });
  const getData2 = await getRes2.json();
  console.log('Server returned after re-login:', JSON.stringify(getData2));

  if (getData2.data === encryptedBlob) {
    console.log('SUCCESS: Data persisted across sessions!');
  } else {
    console.error('FAILURE: Data lost across sessions!');
  }
}

run();
