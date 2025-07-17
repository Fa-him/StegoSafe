// Convert string to ArrayBuffer
function strToBuf(str) {
  return new TextEncoder().encode(str);
}
// Convert ArrayBuffer to string
function bufToStr(buf) {
  return new TextDecoder().decode(buf);
}

// Derive key from password (using PBKDF2)
async function deriveKey(password, salt) {
  const pwUtf8 = strToBuf(password);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', pwUtf8, {name: 'PBKDF2'}, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt message with password
async function encryptMessage(message, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encodedMsg = strToBuf(message);
  const encrypted = await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv: iv},
    key,
    encodedMsg
  );
  // Combine salt + iv + encrypted into one Uint8Array (all base64 encoded later)
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}

// Decrypt message with password
async function decryptMessage(dataB64, password) {
  try {
    const data = Uint8Array.from(atob(dataB64), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const encrypted = data.slice(28);
    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: iv},
      key,
      encrypted
    );
    return bufToStr(decrypted);
  } catch {
    throw new Error("Wrong password or corrupted data");
  }
}

// ===================
// Steganography encode/decode in LSB of pixels
// ===================

function messageToBinary(msg) {
  let bin = '';
  for (let i = 0; i < msg.length; i++) {
    bin += msg.charCodeAt(i).toString(2).padStart(8, '0');
  }
  bin += '1111111111111110'; // delimiter
  return bin;
}

function binaryToMessage(bin) {
  let chars = [];
  for (let i = 0; i < bin.length; i += 8) {
    let byte = bin.substr(i, 8);
    if (byte === '11111110') break;
    chars.push(String.fromCharCode(parseInt(byte, 2)));
  }
  return chars.join('');
}

async function encodeImage(image, message, password = '') {
  const canvas = document.createElement('canvas');
  canvas.width = image.width;
  canvas.height = image.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(image, 0, 0);
  const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

  let msgToEncode = message;
  if (password) {
    msgToEncode = await encryptMessage(message, password);
  }
  const binary = messageToBinary(msgToEncode);

  if (binary.length > imgData.data.length / 4 * 3) {
    throw new Error("Message too long to encode in this image");
  }

  let dataIndex = 0;
  for (let i = 0; i < imgData.data.length && dataIndex < binary.length; i += 4) {
    // R
    imgData.data[i] = (imgData.data[i] & 0xFE) | Number(binary[dataIndex]);
    dataIndex++;
    if (dataIndex >= binary.length) break;
    // G
    imgData.data[i + 1] = (imgData.data[i + 1] & 0xFE) | Number(binary[dataIndex]);
    dataIndex++;
    if (dataIndex >= binary.length) break;
    // B
    imgData.data[i + 2] = (imgData.data[i + 2] & 0xFE) | Number(binary[dataIndex]);
    dataIndex++;
  }

  ctx.putImageData(imgData, 0, 0);
  return canvas;
}

async function decodeImage(image, password = '') {
  const canvas = document.createElement('canvas');
  canvas.width = image.width;
  canvas.height = image.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(image, 0, 0);
  const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

  let binary = '';
  for (let i = 0; i < imgData.data.length; i += 4) {
    binary += (imgData.data[i] & 1).toString();
    binary += (imgData.data[i + 1] & 1).toString();
    binary += (imgData.data[i + 2] & 1).toString();
  }

  const delimiter = '1111111111111110';
  let endIndex = binary.indexOf(delimiter);
  if (endIndex === -1) endIndex = binary.length;
  binary = binary.substring(0, endIndex);

  let message = binaryToMessage(binary);
  if (password) {
    try {
      message = await decryptMessage(message, password);
    } catch {
      message = "Failed to decrypt message: wrong password or corrupted data";
    }
  }
  return message;
}

// ===================
// DOM Handling & Event Listeners
// ===================

window.addEventListener('load', () => {
  const encodeForm = document.getElementById('encodeForm');
  const decodeForm = document.getElementById('decodeForm');
  const output = document.getElementById('output');

  encodeForm.addEventListener('submit', async e => {
    e.preventDefault();
    const fileInput = encodeForm.elements['cover'];
    const messageInput = encodeForm.elements['message'];
    const passwordInput = encodeForm.elements['password'];

    if (!fileInput.files.length) {
      alert('Please select a PNG image to encode');
      return;
    }

    const file = fileInput.files[0];
    if (file.type !== 'image/png') {
      alert('Only PNG images are supported');
      return;
    }

    const img = new Image();
    img.onload = async () => {
      try {
        const canvas = await encodeImage(img, messageInput.value, passwordInput.value);
        canvas.toBlob(blob => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'stego_image.png';
          a.click();
          URL.revokeObjectURL(a.href);
        }, 'image/png');
      } catch (err) {
        alert(err.message);
      }
    };
    img.onerror = () => alert('Failed to load image');
    img.src = URL.createObjectURL(file);
  });

  decodeForm.addEventListener('submit', async e => {
    e.preventDefault();
    output.textContent = '';

    const fileInput = decodeForm.elements['stego'];
    const passwordInput = decodeForm.elements['password'];

    if (!fileInput.files.length) {
      alert('Please select a PNG image to decode');
      return;
    }

    const file = fileInput.files[0];
    if (file.type !== 'image/png') {
      alert('Only PNG images are supported');
      return;
    }

    const img = new Image();
    img.onload = async () => {
      try {
        const message = await decodeImage(img, passwordInput.value);
        output.textContent = 'Secret: ' + message;
      } catch (err) {
        output.textContent = 'Error decoding message';
      }
    };
    img.onerror = () => {
      output.textContent = 'Failed to load image';
    };
    img.src = URL.createObjectURL(file);
  });
});
