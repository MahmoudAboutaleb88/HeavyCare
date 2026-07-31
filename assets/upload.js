// assets/upload.js
//
// Shared helper for uploading an image file straight from the browser to
// Cloudinary (unsigned upload — no secret involved, safe to run client-side).
// Any page that needs image upload includes this file and calls
// uploadImageToCloudinary(file).

let __cloudinaryConfigCache = null;

async function getCloudinaryConfig() {
  if (__cloudinaryConfigCache) return __cloudinaryConfigCache;

  const token = localStorage.getItem('auth_token');
  const res = await fetch('/api/config', {
    headers: { Authorization: 'Bearer ' + token },
  });
  const body = await res.json();

  if (!body.success || !body.data.cloudinary_cloud_name || !body.data.cloudinary_upload_preset) {
    throw new Error('إعدادات رفع الصور غير مكتملة على السيرفر (Cloudinary)');
  }

  __cloudinaryConfigCache = body.data;
  return __cloudinaryConfigCache;
}

/**
 * Uploads a single image File to Cloudinary and returns its public URL.
 * Throws on failure — callers should wrap this in try/catch.
 *
 * @param {File} file
 * @returns {Promise<string>} secure_url of the uploaded image
 */
async function uploadImageToCloudinary(file) {
  if (!file) throw new Error('لم يتم اختيار صورة');
  if (!file.type.startsWith('image/')) throw new Error('الملف المختار مش صورة');
  if (file.size > 8 * 1024 * 1024) throw new Error('حجم الصورة أكبر من 8 ميجا');

  const config = await getCloudinaryConfig();

  const formData = new FormData();
  formData.append('file', file);
  formData.append('upload_preset', config.cloudinary_upload_preset);

  const uploadUrl = 'https://api.cloudinary.com/v1_1/' + config.cloudinary_cloud_name + '/image/upload';

  const res = await fetch(uploadUrl, { method: 'POST', body: formData });
  const body = await res.json();

  if (!res.ok || !body.secure_url) {
    throw new Error(body.error && body.error.message ? body.error.message : 'فشل رفع الصورة');
  }

  return body.secure_url;
}
