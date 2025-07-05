//  Integrantes:
//           Santiago De Andrade
//           Daniel Ross
//           Sebastian Vera
//           Samuel palacios



#include <iostream>
#include <fstream>      // Para manejo de archivos
#include <string>
#include <vector>
#include <chrono>       // Para medir el tiempo
#include <iomanip>      // Para std::setw, std::setfill
#include <sstream>      // Para std::stringstream
#include <cstdio>       // Para remove()

// --- INICIO DE LA LIBRERÍA SHA-256 ---
#include "SHA256.h"
// --- FIN DE LA LIBRERÍA SHA-256 ---

// Definiciones de funciones (prototipos)
char cifrarCaracter(char c);
char descifrarCaracter(char c);
void copiarArchivo(const std::string& origen, const std::string& destino);
void encriptarArchivo(const std::string& entrada, const std::string& salida);
void desencriptarArchivo(const std::string& entrada, const std::string& salida);
std::string generarHashSHA256(const std::string& rutaArchivo);
bool validarHashSHA256(const std::string& rutaArchivoEncriptado, const std::string& hashEsperado);
bool compararArchivos(const std::string& archivo1, const std::string& archivo2);
std::string formatDuration(long long ms); // Función auxiliar para formatear tiempo
long long ejecutarProcesoBase(int N, const std::string& originalFileName);
void ejecutarProcesoOptimizado(int N, const std::string& originalFileName, long long tiempoBase);


int main() {
    // Apellidos de los integrantes para el encabezado del programa fuente
    /*
    * Integrantes del equipo:
    * Santiago De Andrade
    * Sebastian Vera
    * Samuel Palacios
    * Daniel Ross
    */

    std::string originalFileName = "original.txt"; // El archivo original proporcionado

    // El enunciado indica N = 10 para la entrega y evaluación
    int N = 10;

    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "PROCESO BASE" << std::endl;
    long long tiempoBase = ejecutarProcesoBase(N, originalFileName);
    std::cout << "----------------------------------------------------" << std::endl;

    std::cout << std::endl;

    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "PROCESO OPTIMIZADO" << std::endl;
    ejecutarProcesoOptimizado(N, originalFileName, tiempoBase);
    std::cout << "----------------------------------------------------" << std::endl;

    return 0;
}

// Implementación de las funciones

char cifrarCaracter(char c) {
    if (c >= 'A' && c <= 'Z') {
        return 'A' + (c - 'A' + 3) % 26;
    } else if (c >= 'a' && c <= 'z') {
        return 'a' + (c - 'a' + 3) % 26;
    } else if (c >= '0' && c <= '9') {
        return '9' - (c - '0'); // Simétrico
    }
    return c; // Otros caracteres sin cambios
}

char descifrarCaracter(char c) {
    if (c >= 'A' && c <= 'Z') {
        return 'A' + (c - 'A' - 3 + 26) % 26; // +26 para manejar números negativos en C++
    } else if (c >= 'a' && c <= 'z') {
        return 'a' + (c - 'a' - 3 + 26) % 26;
    } else if (c >= '0' && c <= '9') {
        return '9' - (c - '0'); // Es la misma lógica para descifrar el simétrico
    }
    return c;
}

void copiarArchivo(const std::string& origen, const std::string& destino) {
    std::ifstream src(origen, std::ios::binary);
    std::ofstream dst(destino, std::ios::binary);
    if (!src.is_open()) {
        std::cerr << "Error: No se pudo abrir el archivo de origen para copiar: " << origen << std::endl;
        return;
    }
    if (!dst.is_open()) {
        std::cerr << "Error: No se pudo crear/abrir el archivo de destino para copiar: " << destino << std::endl;
        return;
    }
    dst << src.rdbuf();
    src.close();
    dst.close();
}

void encriptarArchivo(const std::string& entrada, const std::string& salida) {
    std::ifstream ifs(entrada);
    std::ofstream ofs(salida);
    if (!ifs.is_open()) {
        std::cerr << "Error: No se pudo abrir el archivo de entrada para encriptar: " << entrada << std::endl;
        return;
    }
    if (!ofs.is_open()) {
        std::cerr << "Error: No se pudo crear/abrir el archivo de salida para encriptar: " << salida << std::endl;
        return;
    }
    char c;
    while (ifs.get(c)) {
        ofs.put(cifrarCaracter(c));
    }
    ifs.close();
    ofs.close();
}

void desencriptarArchivo(const std::string& entrada, const std::string& salida) {
    std::ifstream ifs(entrada);
    std::ofstream ofs(salida);
    if (!ifs.is_open()) {
        std::cerr << "Error: No se pudo abrir el archivo de entrada para desencriptar: " << entrada << std::endl;
        return;
    }
    if (!ofs.is_open()) {
        std::cerr << "Error: No se pudo crear/abrir el archivo de salida para desencriptar: " << salida << std::endl;
        return;
    }
    char c;
    while (ifs.get(c)) {
        ofs.put(descifrarCaracter(c));
    }
    ifs.close();
    ofs.close();
}

// **Requiere una librería SHA-256 externa**
// Si usas una librería como "sha256.h/.cpp", tu función podría verse así:
std::string generarHashSHA256(const std::string& rutaArchivo) {
    std::ifstream file(rutaArchivo, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error al abrir el archivo para hash: " << rutaArchivo << std::endl;
        return "";
    }
    
    // Leer el contenido del archivo
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Usar la librería SHA-256
    SHA256 sha256;
    return sha256(content);
}

bool validarHashSHA256(const std::string& rutaArchivoEncriptado, const std::string& hashEsperado) {
    std::string hashCalculado = generarHashSHA256(rutaArchivoEncriptado);
    return hashCalculado == hashEsperado;
}

bool compararArchivos(const std::string& archivo1, const std::string& archivo2) {
    std::ifstream f1(archivo1, std::ios::binary);
    std::ifstream f2(archivo2, std::ios::binary);

    if (!f1.is_open() || !f2.is_open()) {
        std::cerr << "Error: No se pudieron abrir los archivos para comparar. Archivo1: " << archivo1 << ", Archivo2: " << archivo2 << std::endl;
        return false;
    }

    char c1, c2;
    while (f1.get(c1) && f2.get(c2)) {
        if (c1 != c2) {
            f1.close();
            f2.close();
            return false; // Archivos diferentes
        }
    }
    // Ambos deben haber llegado al final al mismo tiempo y sin diferencias
    bool result = f1.eof() && f2.eof();
    f1.close();
    f2.close();
    return result;
}

std::string formatDuration(long long ms) {
    long long total_seconds = ms / 1000;
    long long hours = total_seconds / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    long long seconds = total_seconds % 60;
    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << hours << ":"
       << std::setw(2) << std::setfill('0') << minutes << ":"
       << std::setw(2) << std::setfill('0') << seconds;
    return ss.str();
}

long long ejecutarProcesoBase(int N, const std::string& originalFileName) {
    auto ti_total_chrono = std::chrono::high_resolution_clock::now();
    // Obtener el tiempo de inicio como milisegundos desde epoch para formato TI
    long long ti_ms_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(ti_total_chrono.time_since_epoch()).count();

    std::cout << "TI: " << formatDuration(ti_ms_since_epoch) << std::endl;

    std::vector<long long> tiempos_por_archivo;
    bool errores_verificacion = false;

    for (int i = 1; i <= N; ++i) {
        auto start_file_process = std::chrono::high_resolution_clock::now();

        std::string copiaFileName = std::to_string(i) + ".txt";
        std::string encriptadoFileName = std::to_string(i) + ".enc"; // Usar .enc para el encriptado
        std::string hashFileName = std::to_string(i) + ".sha";
        std::string desencriptadoFileName = std::to_string(i) + "2.txt";

        // 1. Copiar archivo original.txt a i.txt
        copiarArchivo(originalFileName, copiaFileName);

        // 2. Encriptar i.txt a i.enc y generar hash de i.enc en i.sha
        encriptarArchivo(copiaFileName, encriptadoFileName);
        std::string hash_generado = generarHashSHA256(encriptadoFileName);
        // Guardar hash en un archivo .sha
        std::ofstream hash_ofs(hashFileName);
        if (hash_ofs.is_open()) {
            hash_ofs << hash_generado;
            hash_ofs.close();
        } else {
            std::cerr << "Error: No se pudo crear el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }


        // 3. Validar hash de i.enc y desencriptar i.enc a i2.txt
        std::string hash_leido_para_validacion;
        std::ifstream hash_ifs(hashFileName);
        if (hash_ifs.is_open()) {
            hash_ifs >> hash_leido_para_validacion;
            hash_ifs.close();
        } else {
            std::cerr << "Error: No se pudo leer el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }


        if (!errores_verificacion && validarHashSHA256(encriptadoFileName, hash_leido_para_validacion)) {
            desencriptarArchivo(encriptadoFileName, desencriptadoFileName);
        } else {
            std::cerr << "Error de validación de hash para el archivo " << encriptadoFileName << std::endl;
            errores_verificacion = true;
        }

        // 4. Comparar archivo desencriptado (i2.txt) con el original (original.txt)
        if (!errores_verificacion && !compararArchivos(originalFileName, desencriptadoFileName)) {
            std::cerr << "Error: El archivo desencriptado " << desencriptadoFileName << " no coincide con el original." << std::endl;
            errores_verificacion = true;
        }

        // Limpieza de archivos temporales
        remove(copiaFileName.c_str());
        remove(encriptadoFileName.c_str());
        remove(hashFileName.c_str());
        remove(desencriptadoFileName.c_str());


        auto end_file_process = std::chrono::high_resolution_clock::now();
        auto duration_file = std::chrono::duration_cast<std::chrono::milliseconds>(end_file_process - start_file_process);
        tiempos_por_archivo.push_back(duration_file.count());
        std::cout << "Tiempo " << std::setw(2) << std::setfill('0') << i << " : " << formatDuration(duration_file.count()) << std::endl;
    }

    auto tfin_total_chrono = std::chrono::high_resolution_clock::now();
    // Obtener el tiempo de finalización como milisegundos desde epoch para formato TFIN
    long long tfin_ms_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(tfin_total_chrono.time_since_epoch()).count();

    auto tt_total = std::chrono::duration_cast<std::chrono::milliseconds>(tfin_total_chrono - ti_total_chrono);

    long long sum_tiempos = 0;
    for (long long t : tiempos_por_archivo) {
        sum_tiempos += t;
    }
    long long tppa_ms = (N > 0) ? (sum_tiempos / N) : 0;

    std::cout << "TFIN : " << formatDuration(tfin_ms_since_epoch) << std::endl;
    std::cout << "TPPA : " << formatDuration(tppa_ms) << std::endl;
    std::cout << "TT: " << formatDuration(tt_total.count()) << std::endl;

    if (errores_verificacion) {
        std::cout << "Hubo errores en la verificación final." << std::endl;
    } else {
        std::cout << "No se encontraron errores en la verificación final." << std::endl;
    }

    return tt_total.count();
}

// La implementación de ejecutarProcesoOptimizado será similar,
// pero aquí es donde aplicarás tus estrategias de optimización.
// Por ejemplo, podrías usar hilos (std::thread) para paralelizar el procesamiento de archivos.
// Para usar std::thread, necesitarás #include <thread> y quizás un mutex si compartes recursos.
void ejecutarProcesoOptimizado(int N, const std::string& originalFileName, long long tiempoBase) {
    auto ti_total_chrono = std::chrono::high_resolution_clock::now();
    long long ti_ms_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(ti_total_chrono.time_since_epoch()).count();

    std::cout << "TI: " << formatDuration(ti_ms_since_epoch) << std::endl;

    std::vector<long long> tiempos_por_archivo;
    bool errores_verificacion = false;

    // --- ESTRATEGIA DE OPTIMIZACIÓN: EJEMPLO CON MULTITHREADING (Simplificado) ---
    // Si decides usar hilos, el código aquí se volverá más complejo,
    // gestionando un pool de hilos o lanzando hilos para cada tarea o grupo de tareas.
    // Para una implementación simple, aún secuencial pero mostrando dónde optimizar:
    // Podrías lanzar hilos para procesar bloques de N/X archivos, o para ciertas operaciones.

    for (int i = 1; i <= N; ++i) {
        auto start_file_process = std::chrono::high_resolution_clock::now();

        std::string copiaFileName = std::to_string(i) + ".txt";
        std::string encriptadoFileName = std::to_string(i) + ".enc";
        std::string hashFileName = std::to_string(i) + ".sha";
        std::string desencriptadoFileName = std::to_string(i) + "2.txt";

        // En un escenario optimizado, estas operaciones podrían ser paralelizadas.
        // Por ejemplo:
        // 1. Copiar archivo
        copiarArchivo(originalFileName, copiaFileName);

        // 2. Encriptar y generar hash (podría ser en un hilo separado para varios archivos)
        encriptarArchivo(copiaFileName, encriptadoFileName);
        std::string hash_generado = generarHashSHA256(encriptadoFileName);
        std::ofstream hash_ofs(hashFileName);
        if (hash_ofs.is_open()) {
            hash_ofs << hash_generado;
            hash_ofs.close();
        } else {
            std::cerr << "Error: No se pudo crear el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }

        // 3. Validar hash y desencriptar (podría ser en otro hilo)
        std::string hash_leido_para_validacion;
        std::ifstream hash_ifs(hashFileName);
        if (hash_ifs.is_open()) {
            hash_ifs >> hash_leido_para_validacion;
            hash_ifs.close();
        } else {
            std::cerr << "Error: No se pudo leer el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }

        if (!errores_verificacion && validarHashSHA256(encriptadoFileName, hash_leido_para_validacion)) {
            desencriptarArchivo(encriptadoFileName, desencriptadoFileName);
        } else {
            std::cerr << "Error de validación de hash para el archivo " << encriptadoFileName << std::endl;
            errores_verificacion = true;
        }

        // 4. Comparar archivo desencriptado con el original
        if (!errores_verificacion && !compararArchivos(originalFileName, desencriptadoFileName)) {
            std::cerr << "Error: El archivo desencriptado " << desencriptadoFileName << " no coincide con el original." << std::endl;
            errores_verificacion = true;
        }

        // Limpieza de archivos temporales
        remove(copiaFileName.c_str());
        remove(encriptadoFileName.c_str());
        remove(hashFileName.c_str());
        remove(desencriptadoFileName.c_str());

        auto end_file_process = std::chrono::high_resolution_clock::now();
        auto duration_file = std::chrono::duration_cast<std::chrono::milliseconds>(end_file_process - start_file_process);
        tiempos_por_archivo.push_back(duration_file.count());
        std::cout << "Tiempo " << std::setw(2) << std::setfill('0') << i << " : " << formatDuration(duration_file.count()) << std::endl;
    }

    auto tfin_total_chrono = std::chrono::high_resolution_clock::now();
    long long tfin_ms_since_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(tfin_total_chrono.time_since_epoch()).count();

    auto tt_total = std::chrono::duration_cast<std::chrono::milliseconds>(tfin_total_chrono - ti_total_chrono);

    long long sum_tiempos = 0;
    for (long long t : tiempos_por_archivo) {
        sum_tiempos += t;
    }
    long long tppa_ms = (N > 0) ? (sum_tiempos / N) : 0;

    std::cout << "TFIN : " << formatDuration(tfin_ms_since_epoch) << std::endl;
    std::cout << "TPPA : " << formatDuration(tppa_ms) << std::endl;
    std::cout << "TT: " << formatDuration(tt_total.count()) << std::endl;

    if (errores_verificacion) {
        std::cout << "Hubo errores en la verificación final." << std::endl;
    } else {
        std::cout << "No se encontraron errores en la verificación final." << std::endl;
    }

    // Calcula DF y PM usando el tiempo base pasado como parámetro
    long long df_ms = tiempoBase - tt_total.count();
    double pm_porcentaje = (static_cast<double>(df_ms) / tiempoBase) * 100.0;

    std::cout << "DF: " << formatDuration(df_ms) << std::endl;
    std::cout << "PM: " << std::fixed << std::setprecision(2) << pm_porcentaje << " %" << std::endl;
}
