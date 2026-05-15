const BASE_URL = 'http://127.0.0.1:1234';

async function run() {
  console.log('1. Logging in...');
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'wang@gmail.com', password: 'name' })
  });
  
  const headers = loginRes.headers;
  const setCookies = loginRes.headers.getSetCookie();
  console.log('Set-Cookies:', setCookies);

  const cookieStr = setCookies.join('; ');
  const csrfMatch = cookieStr.match(/_pwd_csrf=([^;]+)/);
  if (!csrfMatch) {
    console.error('CSRF cookie not found in:', setCookies);
    return;
  }
  const csrf = csrfMatch[1];
  console.log('Login OK. CSRF:', csrf);

  // Simulate folder creation
  console.log('2. Creating folder...');
  const encryptedBlob = 'FAKE_ENCRYPTED_BLOB_' + Date.now();

  const putRes = await fetch(`${BASE_URL}/api/vault/folders`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
      'Cookie': cookieStr
    },
    body: JSON.stringify({ data: encryptedBlob })
  });
  console.log('PUT Folders status:', putRes.status);

  console.log('3. Verifying persistence...');
  const getRes = await fetch(`${BASE_URL}/api/vault/folders`, {
    headers: { 'Cookie': cookieStr }
  });
  const getData = await getRes.json();
  console.log('Server returned:', JSON.stringify(getData));

  // RE-LOGIN
  console.log('4. Re-logging in...');
  const loginRes2 = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'wang@gmail.com', password: 'name' })
  });
  const setCookies2 = loginRes2.headers.getSetCookie();
  const cookieStr2 = setCookies2.join('; ');
  
  const getRes2 = await fetch(`${BASE_URL}/api/vault/folders`, {
    headers: { 'Cookie': cookieStr2 }
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
