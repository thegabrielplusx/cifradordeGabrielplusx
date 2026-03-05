/**
 * ============================================================================
 * CIFRADOR DE GABRIELPLUSX - Lógica de Criptografía AES-256
 * ============================================================================
 * 
 * Sistema de cifrado/descifrado utilizando:
 * - AES-256 para encriptación simétrica
 * - PBKDF2 para derivación segura de claves
 * - Librería: CryptoJS
 * 
 * @author Gabriel plusx
 
 */

// ============================================================================
// ELEMENTOS DEL DOM
// ============================================================================

const inputTextoOriginal = document.getElementById('texto-entrada');
const inputClave = document.getElementById('clave');
const areaResultado = document.getElementById('resultado');
const botonCifrar = document.getElementById('btn-cifrar');
const botonDescifrar = document.getElementById('btn-descifrar');
const botonCopiar = document.getElementById('btn-copiar');
const botonDescargar = document.getElementById('btn-descargar');
const botonMostrarClave = document.getElementById('togglePassword');

// ============================================================================
// CONSTANTES DE SEGURIDAD
// ============================================================================

const LONGITUD_MINIMA_CLAVE = 12;
const TAMAÑO_SALT = 128 / 8;
const TAMAÑO_CLAVE = 256 / 32;
const ITERACIONES_PBKDF2 = 300000;
const DELAY_ANIMACION = 400;
const DURACION_ANIMACION = 800;

// ============================================================================
// FUNCIONES DE CRIPTOGRAFÍA
// ============================================================================

function derivarClave(contraseña, salt) {
    return CryptoJS.PBKDF2(contraseña, salt, {
        keySize: TAMAÑO_CLAVE,
        iterations: ITERACIONES_PBKDF2
    });
}

// ============================================================================
// FUNCIONES DE SEGURIDAD Y VALIDACIÓN
// ============================================================================

function sanitizarTexto(textoSinSanitizar) {
    if (!textoSinSanitizar) return '';

    return textoSinSanitizar
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function validarEntrada(texto, clave) {
    if (!texto || !clave) {
        mostrarError("ERROR: ¡Ingresa el texto y la clave!");
        return true;
    }

    if (clave.length < LONGITUD_MINIMA_CLAVE) {
        mostrarError(`ERROR: La clave debe tener al menos ${LONGITUD_MINIMA_CLAVE} caracteres.`);
        return true;
    }

    return false;
}

function mostrarError(mensajeError) {
    areaResultado.value = mensajeError;
    areaResultado.classList.add('animacion-error');

    setTimeout(() => {
        areaResultado.classList.remove('animacion-error');
    }, DURACION_ANIMACION);
}

// ============================================================================
// FUNCIÓN DE CIFRADO
// ============================================================================

function cifrarMensaje() {
    const textoOriginal = sanitizarTexto(inputTextoOriginal.value);
    const claveUsuario = sanitizarTexto(inputClave.value.trim());

    if (validarEntrada(textoOriginal, claveUsuario)) {
        return;
    }

    try {
        areaResultado.classList.add('animacion-cifrado');
        areaResultado.value = 'Cifrando...';

        setTimeout(() => {
            const saltAleatorio = CryptoJS.lib.WordArray.random(TAMAÑO_SALT);
            const claveDerivada = derivarClave(claveUsuario, saltAleatorio);
            const textoCifrado = CryptoJS.AES.encrypt(textoOriginal, claveDerivada, {
                iv: saltAleatorio
            }).toString();

            const saltBase64 = CryptoJS.enc.Base64.stringify(saltAleatorio);
            const mensajeCompleto = saltBase64 + "::" + textoCifrado;

            areaResultado.value = mensajeCompleto;
            inputTextoOriginal.value = '';

            setTimeout(() => {
                areaResultado.classList.remove('animacion-cifrado');
            }, DURACION_ANIMACION);
        }, DELAY_ANIMACION);

    } catch (error) {
        mostrarError("ERROR al cifrar el mensaje. Verifique la entrada.");
        areaResultado.classList.remove('animacion-cifrado');
        console.error("Error de cifrado:", error);
    }
}

// =============================================================g===============
// FUNCIÓN DE DESCIFRADO
// ============================================================================

function descifrarMensaje() {
    const mensajeCifrado = sanitizarTexto(inputTextoOriginal.value) ||
        sanitizarTexto(areaResultado.value);
    const claveUsuario = sanitizarTexto(inputClave.value.trim());

    if (validarEntrada(mensajeCifrado, claveUsuario)) {
        return;
    }

    if (!mensajeCifrado.includes('::')) {
        mostrarError("ERROR: El texto cifrado debe contener el separador '::'.");
        return;
    }

    try {
        areaResultado.classList.add('animacion-descifrado');
        areaResultado.value = 'Descifrando...';

        setTimeout(() => {
            try {
                const partesMensaje = mensajeCifrado.split('::');
                const saltBase64 = partesMensaje[0];
                const textoCifrado = partesMensaje[1];

                const saltRecuperado = CryptoJS.enc.Base64.parse(saltBase64);
                const claveDerivada = derivarClave(claveUsuario, saltRecuperado);

                const bytesDescifrados = CryptoJS.AES.decrypt(textoCifrado, claveDerivada, {
                    iv: saltRecuperado
                });

                const textoDescifrado = bytesDescifrados.toString(CryptoJS.enc.Utf8);

                if (textoDescifrado.length === 0) {
                    areaResultado.classList.remove('animacion-descifrado');
                    mostrarError("ERROR: Clave incorrecta o texto cifrado inválido/corrupto.");
                } else {
                    areaResultado.value = textoDescifrado;
                    inputTextoOriginal.value = '';

                    setTimeout(() => {
                        areaResultado.classList.remove('animacion-descifrado');
                    }, DURACION_ANIMACION);
                }

            } catch (error) {
                areaResultado.classList.remove('animacion-descifrado');
                mostrarError("ERROR crítico al descifrar. Verifique la clave y el mensaje.");
                console.error("Error de descifrado:", error);
            }
        }, DELAY_ANIMACION);

    } catch (error) {
        areaResultado.classList.remove('animacion-descifrado');
        mostrarError("ERROR crítico al descifrar. Verifique la clave y el mensaje.");
        console.error("Error de descifrado:", error);
    }
}

// ============================================================================
// FUNCIONES DE UTILIDAD
// ============================================================================

function copiarResultado() {
    areaResultado.select();
    areaResultado.setSelectionRange(0, 99999);
    document.execCommand("copy");

    const textoOriginalBoton = botonCopiar.textContent;
    botonCopiar.textContent = "¡Copiado!";

    setTimeout(() => {
        botonCopiar.textContent = textoOriginalBoton;
    }, 1500);
}

function descargarComoTXT(contenido) {
    const archivoBlob = new Blob([contenido], {
        type: 'text/plain;charset=utf-8'
    });

    const urlDescarga = URL.createObjectURL(archivoBlob);
    const enlaceDescarga = document.createElement('a');

    enlaceDescarga.href = urlDescarga;
    enlaceDescarga.download = 'encrypted_message.txt';

    document.body.appendChild(enlaceDescarga);
    enlaceDescarga.click();

    document.body.removeChild(enlaceDescarga);
    URL.revokeObjectURL(urlDescarga);
}

function descargarComoPDF(contenido) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    const margenIzquierdo = 15;
    const margenSuperior = 20;
    const anchoMaximo = 180;
    const alturaLinea = 7;

    // Título anónimo
    doc.setFontSize(14);
    doc.setFont(undefined, 'bold');
    doc.text('ENCRYPTED MESSAGE', margenIzquierdo, margenSuperior);

    // Línea separadora
    doc.setLineWidth(0.5);
    doc.line(margenIzquierdo, margenSuperior + 5, margenIzquierdo + anchoMaximo, margenSuperior + 5);

    // Información técnica sin datos identificables
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');
    doc.text('Algorithm: AES-256', margenIzquierdo, margenSuperior + 15);
    doc.text('Key Derivation: PBKDF2', margenIzquierdo, margenSuperior + 21);

    // Advertencia de seguridad
    doc.setFontSize(8);
    doc.setFont(undefined, 'italic');
    doc.text('Keep this file secure. Do not share without encryption key.', margenIzquierdo, margenSuperior + 30);

    // Etiqueta del contenido
    doc.setFontSize(9);
    doc.setFont(undefined, 'bold');
    doc.text('ENCRYPTED DATA:', margenIzquierdo, margenSuperior + 40);

    // Contenido cifrado
    doc.setFont('courier', 'normal');
    doc.setFontSize(8);
    const lineasTexto = doc.splitTextToSize(contenido, anchoMaximo);

    let posicionY = margenSuperior + 48;

    lineasTexto.forEach((linea) => {
        if (posicionY > 280) {
            doc.addPage();
            posicionY = 20;
        }
        doc.text(linea, margenIzquierdo, posicionY);
        posicionY += alturaLinea;
    });

    // Guardar con nombre anónimo
    doc.save('encrypted_data.pdf');
}

function descargarMensajeCifrado() {
    const contenidoDescarga = areaResultado.value;

    if (!contenidoDescarga || !contenidoDescarga.includes('::')) {
        alert("Primero debe CIFRAR un mensaje para descargar el texto cifrado.");
        return;
    }

    const formato = prompt(
        "¿En qué formato deseas descargar el archivo?\n\n" +
        "Escribe:\n" +
        "• 'txt' para archivo de texto (.txt)\n" +
        "• 'pdf' para documento PDF (.pdf)",
        "txt"
    );

    if (!formato) {
        return;
    }

    const formatoLower = formato.toLowerCase().trim();

    if (formatoLower === 'txt') {
        descargarComoTXT(contenidoDescarga);
    } else if (formatoLower === 'pdf') {
        descargarComoPDF(contenidoDescarga);
    } else {
        alert("Formato no válido. Por favor, escribe 'txt' o 'pdf'.");
    }
}

function configurarMostrarClave() {
    if (botonMostrarClave) {
        botonMostrarClave.addEventListener('click', function () {
            const tipoActual = inputClave.getAttribute('type');
            const nuevoTipo = tipoActual === 'password' ? 'text' : 'password';
            inputClave.setAttribute('type', nuevoTipo);

            this.textContent = nuevoTipo === 'text' ? '○' : '●';
        });
    }
}

// ============================================================================
// INICIALIZACIÓN DE LA APLICACIÓN
// ============================================================================

botonCifrar.addEventListener('click', cifrarMensaje);
botonDescifrar.addEventListener('click', descifrarMensaje);
botonCopiar.addEventListener('click', copiarResultado);
botonDescargar.addEventListener('click', descargarMensajeCifrado);

configurarMostrarClave();


// Créditos: Gabriel plusx
// GitHub: https://github.com/thegabrielplusx
