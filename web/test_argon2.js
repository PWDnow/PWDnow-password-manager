const argon2 = require('argon2');
async function test() {
  try {
    const hash = await argon2.hash("wang@gmail.com", { type: argon2.argon2id, memoryCost: 262144, timeCost: 4, parallelism: 1 });
    console.log("Hash:", hash);
  } catch(e) {
    console.error("Crash:", e);
  }
}
test();
