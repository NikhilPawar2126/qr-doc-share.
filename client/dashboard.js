// ✅ File: dashboard.js (SECURE TOKEN VERSION)
const isLocal = location.hostname === "localhost";
const API = isLocal ? "http://localhost:5501" : "https://qrshare-cip8.onrender.com";

const logoutBtn = document.getElementById('logout');
logoutBtn?.addEventListener('click', () => {
  const token = localStorage.getItem('token');
  fetch(`${API}/logout`, {
    method: 'POST',
    headers: { Authorization: token }
  });
  localStorage.clear();
  showToast("Logged out successfully", "success");
  window.location.href = '/';
});

function toggleMenu(btn,event) {
  event.stopPropagation();
  closeAllMenus();
  const menu = btn.nextElementSibling;
  if (menu) menu.classList.toggle("hidden");
}


function closeAllMenus() {
  document.querySelectorAll(".popup-menu").forEach((el) => el.classList.add("hidden"));
}

document.addEventListener("click", function (e) {
  if (!e.target.closest(".file-menu")) {
    closeAllMenus();
  }
});

function renderFileList(files) {
  const search = document.getElementById('searchInput').value.toLowerCase();
  const date = document.getElementById('dateFilter').value;
  const list = document.getElementById('fileList');

  const filtered = files.filter(f =>
    f.name.toLowerCase().includes(search) &&
    (!date || f.createdAt?.startsWith(date))
  );

  list.innerHTML = filtered.length ? '' : '<p>No matching files.</p>';

  filtered.forEach(file => {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.innerHTML = `
      <div class="file-top">
        <span class="file-name">${file.name}</span>
        <div class="file-menu">
          <button class="dots" onclick="toggleMenu(this, event)">⋮</button>
          <div class="popup-menu hidden">
            <button onclick="renameFile('${file.docId}', '${file.name}')">✏️ Rename</button>
            <button onclick="deleteFile('${file.docId}')">❌ Delete</button>
          </div>
        </div>
      </div>
      <div class="date">${file.createdAt ? new Date(file.createdAt).toLocaleString() : '—'}</div>
    `;
    list.appendChild(div);
  });
}

function renameFile(docId, oldName) {
  const newName = prompt("Rename to:", oldName);
  if (!newName || newName === oldName) return;
  fetch(`${API}/files/${docId}/rename`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: localStorage.getItem('token')
    },
    body: JSON.stringify({ newName })
  }).then(() => {
    showToast("Renamed", "success");
    showFilesAndQR();
  });
}

function deleteFile(docId) {
  if (!confirm("Delete this file?")) return;
  fetch(`${API}/files/${docId}`, {
    method: 'DELETE',
    headers: {
      Authorization: localStorage.getItem('token')
    }
  }).then(() => {
    showToast("Deleted", "success");
    showFilesAndQR();
  });
}

function showFilesAndQR() {
  fetch(`${API}/files`, {
    headers: {
      Authorization: localStorage.getItem('token')
    }
  })
    .then(res => res.json())
    .then(data => {
      renderFileList(data.files || []);
      renderQR();
    })
    .catch(() => {
      document.getElementById('fileList').innerHTML = '<p style="color:red;">Failed to load files</p>';
    });
}

function renderQR() {
  const userId = localStorage.getItem('userId');
  const password = localStorage.getItem('password');
  if (!userId || !password) return;
  const qrUrl = `${API}/shared.html?docId=${localStorage.getItem('docId') || ''}`;

  document.getElementById('qrPreview').innerHTML = `
    <img id="qrImg" src="https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(qrUrl)}&size=200x200" />
    <div class="button-row">
      <button class="share-btn" onclick="window.open('${qrUrl}', '_blank')">Open</button>
      <button class="pdf-btn" onclick="downloadQR('${qrUrl}')">Download PDF</button>
    </div>
  `;
}

function downloadQR(url) {
  const img = new Image();
  img.src = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(url)}&size=200x200`;
  img.onload = () => {
    const wrapper = document.createElement('div');
    wrapper.appendChild(img);
    html2pdf().from(wrapper).save("SharedQR.pdf");
  };
}

function toggleCard(id) {
  const content = document.getElementById(`content-${id}`);
  const icon = document.getElementById(`icon-${id}`);
  content.classList.toggle('active');
  icon.style.transform = content.classList.contains('active') ? "rotate(180deg)" : "rotate(0deg)";
}

const uploadForm = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');
const qrPreview = document.getElementById('qrPreviewUpload');
const dropArea = document.getElementById('dropArea');

uploadForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const file = fileInput.files[0];
  const password = localStorage.getItem('password');
  const token = localStorage.getItem('token');

  if (!file) {
    showToast("Please select a file before uploading", "error");
    fileInput.click();
    return;
  }
  if (!password || !token) {
    showToast("Missing session. Please login again.", "error");
    return;
  }

  dropArea.innerHTML = '<p>Uploading...</p>';
  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);

  const res = await fetch(`${API}/upload`, {
    method: 'POST',
    body: formData,
    headers: { Authorization: token }
  });

  const data = await res.json();
  if (data.qr) {
    qrPreview.innerHTML = `
      <h4>QR Updated</h4>
      <img src="${data.qr}" />
    `;
    localStorage.setItem('docId', data.qrPageUrl.split('docId=')[1] || '');
    showFilesAndQR();
    showToast("Uploaded", "success");
    fileInput.value = '';
    dropArea.innerHTML = '<p><i class="fa-solid fa-cloud-arrow-up"></i> Drop file here or click to browse</p>';
    setTimeout(showFilesAndQR, 800);
  } else {
    showToast(data.error || "Upload failed", "error");
    dropArea.innerHTML = '<p><i class="fa-solid fa-cloud-arrow-up"></i> Drop file here or click to browse</p>';
  }
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) {
    dropArea.innerHTML = `<p>Selected: ${fileInput.files[0].name}</p>`;
  }
});

dropArea.addEventListener('click', () => fileInput.click());
dropArea.addEventListener('dragover', e => {
  e.preventDefault();
  dropArea.classList.add('drag-over');
});
dropArea.addEventListener('dragleave', () => dropArea.classList.remove('drag-over'));
dropArea.addEventListener('drop', e => {
  e.preventDefault();
  dropArea.classList.remove('drag-over');
  fileInput.files = e.dataTransfer.files;
  dropArea.innerHTML = `<p>Dropped: ${fileInput.files[0].name}</p>`;
});

const contactForm = document.getElementById('contactForm');
contactForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const { name, email, message } = e.target;
  if (!name.value || !email.value || !message.value)
    return showToast("Please fill all fields", "error");

  const res = await fetch(`${API}/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: name.value,
      email: email.value,
      message: message.value
    })
  });

  const data = await res.json();
  showToast(data.success ? "Message sent" : data.error, data.success ? "success" : "error");
});

window.addEventListener('DOMContentLoaded', () => {
  const userId = localStorage.getItem('userId');
  const password = localStorage.getItem('password');

  if (!userId || !password) console.warn("Missing login session.");
  else console.log("✅ Session loaded:", { userId, password });

  document.getElementById("username").textContent = userId || 'Guest';
  showFilesAndQR();

  document.getElementById('searchInput')?.addEventListener('input', showFilesAndQR);
  document.getElementById('dateFilter')?.addEventListener('input', showFilesAndQR);

  const toggle = document.getElementById("togglePassword");
  const input = document.getElementById("filePassword");
  toggle?.addEventListener("click", () => {
    input.type = input.type === "password" ? "text" : "password";
    toggle.classList.toggle("fa-eye");
    toggle.classList.toggle("fa-eye-slash");
  });
});

function showToast(msg, type = "success") {
  const toast = document.getElementById('toast');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  toast.style.display = "block";
  setTimeout(() => toast.style.display = "none", 3000);
}
