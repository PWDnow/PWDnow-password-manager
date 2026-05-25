import fetch from 'node-fetch';

async function testC01() {
  const res = await fetch('http://127.0.0.1:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'test@example.com', password: 'password' })
  });
  
  if (res.status === 500) {
    console.error('C-01 FAILED: Received 500 on login');
    process.exit(1);
  } else if (res.status === 200 || res.status === 403 || res.status === 400) {
    console.log('C-01 PASSED: Received ' + res.status);
    process.exit(0);
  } else {
    console.warn('Unexpected status: ' + res.status);
    process.exit(0);
  }
}

testC01();
