/**
 * Lógica Criptográfica (AES-256 con PBKDF2 para derivación de clave)
 * Utiliza la librería CryptoJS.
 */

// --- Obtener Elementos del DOM ---
const textoEntrada = document.getElementById('texto-entrada');
const claveInput = document.getElementById('clave');
const resultado = document.getElementById('resultado');
const btnCifrar = document.getElementById('btn-cifrar');
const btnDescifrar = document.getElementById('btn-descifrar');
const btnCopiar = document.getElementById('btn-copiar');
const btnDescargar = document.getElementById('btn-descargar');
const togglePasswordButton = document.getElementById('togglePassword'); // Toggle de visibilidad

// --- Constantes de Seguridad (PBKDF2 para derivación de clave) ---
const MIN_CLAVE_LENGTH = 12; // Longitud mínima de la clave recomendada
const SALT_SIZE = 128 / 8; // 16 bytes para el Salt (Vector de Inicialización IV)
const KEY_SIZE = 256 / 32; // 8 words (256 bits para AES-256)
const ITERATIONS = 1000;   // Rondas de hashing. Mínimo recomendado.

/**
 * Deriva una clave criptográfica fuerte utilizando PBKDF2.
 * @param {string} clave - La contraseña del usuario.
 * @param {CryptoJS.lib.WordArray} salt - El salt aleatorio.
 * @returns {CryptoJS.lib.WordArray} La clave derivada.
 */
function deriveKey(clave, salt) {
    return CryptoJS.PBKDF2(clave, salt, {
        keySize: KEY_SIZE,
        iterations: ITERATIONS
    });
}

// -----------------------------------------------------------------
//                             Utilidades de Seguridad
// -----------------------------------------------------------------

/**
 * Sanitiza una cadena de texto para prevenir ataques de Cross-Site Scripting (XSS).
 * Elimina cualquier código HTML y JavaScript, dejando solo texto plano.
 * @param {string} str - La cadena de texto a limpiar.
 * @returns {string} La cadena de texto sanitizada.
 */
function sanitizeInput(str) {
    if (!str) return '';
    // Un método simple para escapar caracteres HTML especiales.
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
}

/**
 * Valida la entrada de la clave y el texto.
 * @param {string} texto - El texto de entrada (a cifrar o descifrar).
 * @param {string} clave - La clave ingresada por el usuario.
 * @returns {boolean} Retorna true si la validación falla.
 */
function validateInput(texto, clave) {
    if (!texto || !clave) {
        resultado.value = "ERROR: ¡Ingresa el texto y la clave!";
        return true;
    }
    if (clave.length < MIN_CLAVE_LENGTH) {
        resultado.value = `ERROR: La clave debe tener al menos ${MIN_CLAVE_LENGTH} caracteres.`;
        return true;
    }
    return false;
}

// -----------------------------------------------------------------
//                             Cifrado
// -----------------------------------------------------------------

/**
 * Función principal para CIFRAR el mensaje.
 */
function cifrarMensaje() {
    // Aplicar SANITIZACIÓN a las entradas
    const texto = sanitizeInput(textoEntrada.value); 
    const clave = sanitizeInput(claveInput.value.trim()); 

    if (validateInput(texto, clave)) {
        return;
    }

    try {
        // 1. Generar un 'salt' aleatorio para seguridad y como IV.
        const salt = CryptoJS.lib.WordArray.random(SALT_SIZE);
        
        // 2. Derivar la clave criptográfica a partir de la contraseña.
        const key = deriveKey(clave, salt);

        // 3. Cifrar el mensaje con AES-256. El salt se usa como IV.
        const cifrado = CryptoJS.AES.encrypt(texto, key, {
            iv: salt
        }).toString();

        // 4. Formato de salida: Base64(Salt) + "::" + Texto Cifrado.
        const saltBase64 = CryptoJS.enc.Base64.stringify(salt);
        const mensajeCompleto = saltBase64 + "::" + cifrado; 
        
        resultado.value = mensajeCompleto;
        textoEntrada.value = ''; 

    } catch (error) {
        resultado.value = "ERROR al cifrar el mensaje. Verifique la entrada.";
        console.error("Error de cifrado:", error);
    }
}

// -----------------------------------------------------------------
//                            Descifrado
// -----------------------------------------------------------------

/**
 * Función principal para DESCIFRAR el mensaje.
 */
function descifrarMensaje() {
    // Aplicar SANITIZACIÓN a las entradas
    const mensajeCompleto = sanitizeInput(textoEntrada.value) || sanitizeInput(resultado.value); 
    const clave = sanitizeInput(claveInput.value.trim());
    
    if (validateInput(mensajeCompleto, clave)) {
        return;
    }

    // Validación específica del formato cifrado
    if (!mensajeCompleto.includes('::')) {
        resultado.value = "ERROR: El texto cifrado debe contener el separador '::'.";
        return;
    }

    try {
        // 1. Separar el salt y el texto cifrado.
        const partes = mensajeCompleto.split('::');
        const saltBase64 = partes[0];
        const textoCifrado = partes[1];
        
        // 2. Deserializar el salt para usarlo como IV y en PBKDF2.
        const salt = CryptoJS.enc.Base64.parse(saltBase64);
        
        // 3. Derivar la clave con el mismo salt usado durante el cifrado.
        const key = deriveKey(clave, salt);
        
        // 4. Descifrar el mensaje
        const bytes = CryptoJS.AES.decrypt(textoCifrado, key, {
            iv: salt
        });

        const descifrado = bytes.toString(CryptoJS.enc.Utf8);

        if (descifrado.length === 0) {
            resultado.value = "ERROR: Clave incorrecta o texto cifrado inválido/corrupto.";
        } else {
            resultado.value = descifrado;
            textoEntrada.value = ''; 
        }

    } catch (error) {
        resultado.value = "ERROR crítico al descifrar. Verifique la clave y el mensaje.";
        console.error("Error de descifrado:", error);
    }
}

// -----------------------------------------------------------------
//                             Utilidades
// -----------------------------------------------------------------

/**
 * Copia el contenido del área de resultado al portapapeles.
 */
function copiarResultado() {
    resultado.select();
    resultado.setSelectionRange(0, 99999);
    
    // Uso moderno del API de portapapeles (navigator.clipboard) recomendado, pero se mantiene execCommand por compatibilidad.
    document.execCommand("copy"); 

    // Feedback visual al usuario
    const valorOriginal = btnCopiar.textContent;
    btnCopiar.textContent = "¡Copiado!";
    setTimeout(() => {
        btnCopiar.textContent = valorOriginal;
    }, 1500);
}

/**
 * Descarga el texto cifrado como un archivo de texto (.txt).
 */
function descargarMensajeCifrado() {
    const textoParaDescargar = resultado.value;

    if (!textoParaDescargar || !textoParaDescargar.includes('::')) {
        alert("Primero debe CIFRAR un mensaje para descargar el texto cifrado.");
        return;
    }

    // Creación dinámica de Blob para descarga
    const blob = new Blob([textoParaDescargar], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = 'mensaje_cifrado_aes.txt';
    
    document.body.appendChild(a);
    a.click();
    
    // Limpieza de elementos y recursos
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Configura la funcionalidad del botón 'Toggle Password'.
 */
function setupPasswordToggle() {
    if (togglePasswordButton) {
        togglePasswordButton.addEventListener('click', function() {
            // Alternar el tipo de atributo entre 'password' y 'text'
            const type = claveInput.getAttribute('type') === 'password' ? 'text' : 'password';
            claveInput.setAttribute('type', type);
            
            // Cambiar el ícono ('●' para mostrar, '○' para ocultar)
            this.textContent = type === 'text' ? '○' : '●'; 
        });
    }
}

// -----------------------------------------------------------------
//                           Inicialización
// -----------------------------------------------------------------

// Asignación de Event Handlers
btnCifrar.addEventListener('click', cifrarMensaje);
btnDescifrar.addEventListener('click', descifrarMensaje);
btnCopiar.addEventListener('click', copiarResultado);
btnDescargar.addEventListener('click', descargarMensajeCifrado);

// Configurar el 'ojito'
setupPasswordToggle();


//Créditos a Gabriel plusx