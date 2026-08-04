/**
 * VULPS CIS — Global JavaScript Application Logic
 * Interactive UI components, client-side validation, flash message dismissals, and utility helpers.
 */

document.addEventListener('DOMContentLoaded', () => {
  initFlashDismiss();
  initCounterUp();
  initFormValidations();
  initDropZone();
  initCodeCopyButtons();
});

/* ── Flash Auto-dismiss & Dismiss Button ───────────────── */
function initFlashDismiss() {
  const flashes = document.querySelectorAll('.flash');
  flashes.forEach(flash => {
    // Auto dismiss after 6 seconds
    const timer = setTimeout(() => {
      dismissFlash(flash);
    }, 6000);

    const dismissBtn = flash.querySelector('.flash-dismiss');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        clearTimeout(timer);
        dismissFlash(flash);
      });
    }
  });
}

function dismissFlash(flashEl) {
  flashEl.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
  flashEl.style.opacity = '0';
  flashEl.style.transform = 'translateY(-6px)';
  setTimeout(() => flashEl.remove(), 250);
}

/* ── Counter Up Animation for Stat Cards ───────────────── */
function initCounterUp() {
  const values = document.querySelectorAll('.card-value[data-count]');
  values.forEach(el => {
    const target = parseInt(el.getAttribute('data-count'), 10);
    if (isNaN(target)) return;

    let current = 0;
    const duration = 600; // ms
    const stepTime = 16;  // ~60fps
    const steps = duration / stepTime;
    const increment = target / steps;

    if (target === 0) {
      el.textContent = '0';
      return;
    }

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        el.textContent = target.toLocaleString();
        clearInterval(timer);
      } else {
        el.textContent = Math.floor(current).toLocaleString();
      }
    }, stepTime);
  });
}

/* ── Form Real-Time Validations ────────────────────────── */
function initFormValidations() {
  const forms = document.querySelectorAll('form[data-validate]');
  forms.forEach(form => {
    const inputs = form.querySelectorAll('input, select, textarea');

    inputs.forEach(input => {
      input.addEventListener('blur', () => validateField(input));
      input.addEventListener('input', () => {
        if (input.classList.contains('invalid')) {
          validateField(input);
        }
        updateCharacterCount(input);
      });
    });

    form.addEventListener('submit', (e) => {
      let isValid = true;
      inputs.forEach(input => {
        if (!validateField(input)) {
          isValid = false;
        }
      });
      if (!isValid) {
        e.preventDefault();
        const firstInvalid = form.querySelector('.invalid');
        if (firstInvalid) firstInvalid.focus();
      }
    });
  });
}

function validateField(input) {
  if (input.type === 'hidden') return true;

  const group = input.closest('.form-group') || input.parentElement;
  const errorEl = group ? group.querySelector('.field-error') : null;
  let message = '';
  let valid = true;

  // Required Check
  if (input.hasAttribute('required') && !input.value.trim()) {
    valid = false;
    message = 'Este campo es obligatorio.';
  }

  // Minlength Check
  if (valid && input.getAttribute('minlength')) {
    const min = parseInt(input.getAttribute('minlength'), 10);
    if (input.value.trim().length < min) {
      valid = false;
      message = `Debe tener al menos ${min} caracteres.`;
    }
  }

  // Hostname / Regex Pattern Check
  if (valid && input.dataset.pattern === 'hostname' && input.value.trim()) {
    const hostnameRegex = /^[a-zA-Z0-9._-]+$/;
    if (!hostnameRegex.test(input.value.trim())) {
      valid = false;
      message = 'Hostname no válido (solo letras, números, puntos y guiones).';
    }
  }

  // File CSV Check
  if (valid && input.type === 'file' && input.hasAttribute('required')) {
    if (input.files.length === 0) {
      valid = false;
      message = 'Seleccioná un archivo CSV.';
    } else {
      const fileName = input.files[0].name;
      if (!fileName.endsWith('.csv')) {
        valid = false;
        message = 'El archivo debe tener extensión .csv';
      }
    }
  }

  // Update UI classes & feedback
  if (!valid) {
    input.classList.add('invalid');
    input.classList.remove('valid');
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.classList.add('visible');
    }
  } else {
    input.classList.remove('invalid');
    if (input.value.trim()) {
      input.classList.add('valid');
    } else {
      input.classList.remove('valid');
    }
    if (errorEl) {
      errorEl.textContent = '';
      errorEl.classList.remove('visible');
    }
  }

  return valid;
}

function updateCharacterCount(input) {
  const max = input.getAttribute('maxlength');
  if (!max) return;
  const group = input.closest('.form-group');
  if (!group) return;
  const countEl = group.querySelector('.field-count');
  if (countEl) {
    const current = input.value.length;
    countEl.textContent = `${current}/${max}`;
  }
}

/* ── Drag & Drop CSV Import ────────────────────────────── */
function initDropZone() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file');
  if (!dropZone || !fileInput) return;

  const fileNameDisplay = dropZone.querySelector('.dz-filename');

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('drag-over');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drag-over');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      fileInput.files = files;
      handleFileSelected(files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  function handleFileSelected(file) {
    if (fileNameDisplay) {
      fileNameDisplay.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    }
    dropZone.classList.add('has-file');
    validateField(fileInput);
  }
}

/* ── Copy-to-Clipboard Button ───────────────────────────── */
function initCodeCopyButtons() {
  document.addEventListener('click', (e) => {
    if (e.target && e.target.classList.contains('modal-code-copy')) {
      const btn = e.target;
      const targetId = btn.getAttribute('data-target');
      const codeEl = document.getElementById(targetId);
      if (codeEl) {
        navigator.clipboard.writeText(codeEl.textContent).then(() => {
          const originalText = btn.textContent;
          btn.textContent = '¡Copiado!';
          btn.classList.add('copied');
          setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('copied');
          }, 2000);
        });
      }
    }
  });
}
