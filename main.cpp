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
#include <thread>       // Para std::this_thread::sleep_for
#include <thread>       // Para multithreading
#include <mutex>        // Para sincronización
#include <future>       // Para std::async
#include <immintrin.h>  // Para instrucciones SIMD (AVX/SSE)
#include <windows.h>    // Para optimizaciones específicas de Windows

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
std::string formatDuration(long long microseconds);
long long ejecutarProcesoBase(int N, const std::string& originalFileName);
void ejecutarProcesoOptimizado(int N, const std::string& originalFileName, long long tiempoBase);
void procesarArchivo(int i, const std::string& originalFileName, std::vector<long long>& tiempos_por_archivo, std::mutex& mtx, bool& errores_verificacion);
void optimizarConfiguracionWindows();
bool tieneCapacidadesSIMD();
void cifrarChunkOptimizado(char* buffer, size_t size);
void descifrarChunkOptimizado(char* buffer, size_t size);
void cifrarChunkSIMD(char* buffer, size_t size);
void descifrarChunkSIMD(char* buffer, size_t size);

// Función para detectar capacidades SIMD del procesador
bool tieneCapacidadesSIMD() {
    // Por ahora, asumimos que las CPUs modernas tienen SSE4.2
    // En una implementación real, usaríamos __cpuid o IsProcessorFeaturePresent
    return false; // Fallback: usar algoritmo tradicional para evitar errores
}

// Función de cifrado que usa SIMD si está disponible, sino tradicional
void cifrarChunkOptimizado(char* buffer, size_t size) {
    if (tieneCapacidadesSIMD()) {
        cifrarChunkSIMD(buffer, size);
    } else {
        // Fallback a método tradicional
        for (size_t i = 0; i < size; ++i) {
            buffer[i] = cifrarCaracter(buffer[i]);
        }
    }
}

// Función de descifrado que usa SIMD si está disponible, sino tradicional
void descifrarChunkOptimizado(char* buffer, size_t size) {
    if (tieneCapacidadesSIMD()) {
        descifrarChunkSIMD(buffer, size);
    } else {
        // Fallback a método tradicional
        for (size_t i = 0; i < size; ++i) {
            buffer[i] = descifrarCaracter(buffer[i]);
        }
    }
}

// Función optimizada de cifrado usando SIMD
void cifrarChunkSIMD(char* buffer, size_t size) {
    // Procesar 16 caracteres a la vez usando SSE
    size_t simd_size = size - (size % 16);
    
    for (size_t i = 0; i < simd_size; i += 16) {
        // Cargar 16 caracteres en un registro SSE
        __m128i chars = _mm_loadu_si128((__m128i*)(buffer + i));
        
        // Crear máscaras para diferentes rangos de caracteres
        __m128i upper_mask = _mm_set1_epi8('A');
        __m128i upper_end = _mm_set1_epi8('Z');
        __m128i lower_mask = _mm_set1_epi8('a');
        __m128i lower_end = _mm_set1_epi8('z');
        __m128i digit_mask = _mm_set1_epi8('0');
        __m128i digit_end = _mm_set1_epi8('9');
        
        // Detectar letras mayúsculas (usando comparaciones disponibles)
        __m128i upper_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(upper_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(upper_end, _mm_set1_epi8(1)))
        );
        
        // Detectar letras minúsculas
        __m128i lower_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(lower_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(lower_end, _mm_set1_epi8(1)))
        );
        
        // Detectar dígitos
        __m128i digit_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(digit_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(digit_end, _mm_set1_epi8(1)))
        );
        
        // Aplicar transformaciones
        __m128i upper_shifted = _mm_add_epi8(chars, _mm_set1_epi8(3));
        __m128i lower_shifted = _mm_add_epi8(chars, _mm_set1_epi8(3));
        __m128i digits_symmetric = _mm_sub_epi8(_mm_set1_epi8('9'), _mm_sub_epi8(chars, digit_mask));
        
        // Combinar resultados
        __m128i result = _mm_or_si128(
            _mm_or_si128(
                _mm_and_si128(upper_range, upper_shifted),
                _mm_and_si128(lower_range, lower_shifted)
            ),
            _mm_and_si128(digit_range, digits_symmetric)
        );
        
        // Guardar resultado
        _mm_storeu_si128((__m128i*)(buffer + i), result);
    }
    
    // Procesar caracteres restantes de forma tradicional
    for (size_t i = simd_size; i < size; ++i) {
        buffer[i] = cifrarCaracter(buffer[i]);
    }
}

// Función optimizada de descifrado usando SIMD
void descifrarChunkSIMD(char* buffer, size_t size) {
    // Procesar 16 caracteres a la vez usando SSE
    size_t simd_size = size - (size % 16);
    
    for (size_t i = 0; i < simd_size; i += 16) {
        // Cargar 16 caracteres en un registro SSE
        __m128i chars = _mm_loadu_si128((__m128i*)(buffer + i));
        
        // Crear máscaras para diferentes rangos de caracteres
        __m128i upper_mask = _mm_set1_epi8('A');
        __m128i upper_end = _mm_set1_epi8('Z');
        __m128i lower_mask = _mm_set1_epi8('a');
        __m128i lower_end = _mm_set1_epi8('z');
        __m128i digit_mask = _mm_set1_epi8('0');
        __m128i digit_end = _mm_set1_epi8('9');
        
        // Detectar letras mayúsculas (usando comparaciones disponibles)
        __m128i upper_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(upper_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(upper_end, _mm_set1_epi8(1)))
        );
        
        // Detectar letras minúsculas
        __m128i lower_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(lower_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(lower_end, _mm_set1_epi8(1)))
        );
        
        // Detectar dígitos
        __m128i digit_range = _mm_and_si128(
            _mm_cmpgt_epi8(chars, _mm_sub_epi8(digit_mask, _mm_set1_epi8(1))),
            _mm_cmplt_epi8(chars, _mm_add_epi8(digit_end, _mm_set1_epi8(1)))
        );
        
        // Aplicar transformaciones inversas
        __m128i upper_shifted = _mm_sub_epi8(chars, _mm_set1_epi8(3));
        __m128i lower_shifted = _mm_sub_epi8(chars, _mm_set1_epi8(3));
        __m128i digits_symmetric = _mm_sub_epi8(_mm_set1_epi8('9'), _mm_sub_epi8(chars, digit_mask));
        
        // Combinar resultados
        __m128i result = _mm_or_si128(
            _mm_or_si128(
                _mm_and_si128(upper_range, upper_shifted),
                _mm_and_si128(lower_range, lower_shifted)
            ),
            _mm_and_si128(digit_range, digits_symmetric)
        );
        
        // Guardar resultado
        _mm_storeu_si128((__m128i*)(buffer + i), result);
    }
    
    // Procesar caracteres restantes de forma tradicional
    for (size_t i = simd_size; i < size; ++i) {
        buffer[i] = descifrarCaracter(buffer[i]);
    }
}

int main() {
    // Apellidos de los integrantes para el encabezado del programa fuente
    /*
    * Integrantes del equipo:
    * Santiago De Andrade
    * Sebastian Vera
    * Samuel Palacios
    * Daniel Ross
    */

    // Optimización específica de Windows
    optimizarConfiguracionWindows();

    std::string originalFileName = "original.txt"; // El archivo original proporcionado

    // El enunciado indica N = 10 para la entrega y evaluación
    int N = 10;

    long long tiempoBase = ejecutarProcesoBase(N, originalFileName);

    std::cout << std::endl;

    ejecutarProcesoOptimizado(N, originalFileName, tiempoBase);

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
        std::cout << "Error: No se pudo abrir el archivo de origen para copiar: " << origen << std::endl;
        return;
    }
    if (!dst.is_open()) {
        std::cout << "Error: No se pudo crear/abrir el archivo de destino para copiar: " << destino << std::endl;
        return;
    }
    
    // Copiar carácter por carácter para evitar problemas con chunks
    dst << src.rdbuf();
    
    src.close();
    dst.close();
}

void encriptarArchivo(const std::string& entrada, const std::string& salida) {
    std::ifstream ifs(entrada, std::ios::binary);
    std::ofstream ofs(salida, std::ios::binary);
    
    if (!ifs.is_open()) {
        std::cout << "Error: No se pudo abrir el archivo de entrada para encriptar: " << entrada << std::endl;
        return;
    }
    if (!ofs.is_open()) {
        std::cout << "Error: No se pudo crear/abrir el archivo de salida para encriptar: " << salida << std::endl;
        return;
    }
    
    // Procesar carácter por carácter
    char c;
    while (ifs.get(c)) {
        char encriptado = cifrarCaracter(c);
        ofs.put(encriptado);
    }
    
    ifs.close();
    ofs.close();
}

void desencriptarArchivo(const std::string& entrada, const std::string& salida) {
    std::ifstream ifs(entrada, std::ios::binary);
    std::ofstream ofs(salida, std::ios::binary);
    
    if (!ifs.is_open()) {
        std::cout << "Error: No se pudo abrir el archivo de entrada para desencriptar: " << entrada << std::endl;
        return;
    }
    if (!ofs.is_open()) {
        std::cout << "Error: No se pudo crear/abrir el archivo de salida para desencriptar: " << salida << std::endl;
        return;
    }
    
    // Procesar carácter por carácter
    char c;
    while (ifs.get(c)) {
        char desencriptado = descifrarCaracter(c);
        ofs.put(desencriptado);
    }
    
    ifs.close();
    ofs.close();
}

// **Requiere una librería SHA-256 externa**
// Si usas una librería como "sha256.h/.cpp", tu función podría verse así:
std::string generarHashSHA256(const std::string& rutaArchivo) {
    std::ifstream file(rutaArchivo, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Error al abrir el archivo para hash: " << rutaArchivo << std::endl;
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
        std::cout << "Error: No se pudieron abrir los archivos para comparar. Archivo1: " << archivo1 << ", Archivo2: " << archivo2 << std::endl;
        return false;
    }

    // Comparar carácter por carácter
    char c1, c2;
    size_t pos = 0;
    
    while (true) {
        bool f1_has_data = static_cast<bool>(f1.get(c1));
        bool f2_has_data = static_cast<bool>(f2.get(c2));
        
        // Si ambos llegaron al final al mismo tiempo, son iguales
        if (!f1_has_data && !f2_has_data) {
            f1.close();
            f2.close();
            return true;
        }
        
        // Si solo uno llegó al final, tienen diferentes longitudes
        if (f1_has_data != f2_has_data) {
            f1.close();
            f2.close();
            return false; // Diferentes longitudes
        }
        
        // Si ambos tienen datos pero son diferentes
        if (c1 != c2) {
            f1.close();
            f2.close();
            return false; // Contenido diferente
        }
        
        pos++;
    }
}

std::string formatDuration(long long microseconds) {
    if (microseconds < 0) {
        return "00:00:00.000";
    }
    
    long long total_milliseconds = microseconds / 1000;
    long long remaining_microseconds = microseconds % 1000;
    
    long long total_seconds = total_milliseconds / 1000;
    long long milliseconds = total_milliseconds % 1000;
    
    long long hours = total_seconds / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    long long seconds = total_seconds % 60;
    
    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << hours << ":"
       << std::setw(2) << std::setfill('0') << minutes << ":"
       << std::setw(2) << std::setfill('0') << seconds << "."
       << std::setw(3) << std::setfill('0') << milliseconds;
    
    return ss.str();
}

long long ejecutarProcesoBase(int N, const std::string& originalFileName) {
    auto ti_total_chrono = std::chrono::high_resolution_clock::now();
    
    std::cout << "---------------------------------------------------------------" << std::endl;
    std::cout << "PROCESO BASE" << std::endl;
    std::cout.flush();
    std::cout << "TI: " << formatDuration(0) << std::endl;

    std::vector<long long> tiempos_por_archivo;
    bool errores_verificacion = false;

    for (int i = 1; i <= N; ++i) {
        auto start_file_process = std::chrono::high_resolution_clock::now();

        std::string copiaFileName = std::to_string(i) + ".txt";
        std::string encriptadoFileName = std::to_string(i) + ".enc";
        std::string hashFileName = std::to_string(i) + ".sha";
        std::string desencriptadoFileName = std::to_string(i) + "2.txt";

        copiarArchivo(originalFileName, copiaFileName);
        encriptarArchivo(copiaFileName, encriptadoFileName);
        std::string hash_generado = generarHashSHA256(copiaFileName);
        std::ofstream hash_ofs(hashFileName);
        if (hash_ofs.is_open()) {
            hash_ofs << hash_generado;
            hash_ofs.close();
        } else {
            std::cout << "Error: No se pudo crear el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }

        desencriptarArchivo(encriptadoFileName, desencriptadoFileName);
        std::string hash_leido_para_validacion;
        std::ifstream hash_ifs(hashFileName);
        if (hash_ifs.is_open()) {
            hash_ifs >> hash_leido_para_validacion;
            hash_ifs.close();
        } else {
            std::cout << "Error: No se pudo leer el archivo hash: " << hashFileName << std::endl;
            errores_verificacion = true;
        }

        std::string hash_desencriptado = generarHashSHA256(desencriptadoFileName);
        if (!errores_verificacion && hash_desencriptado != hash_leido_para_validacion) {
            std::cout << "Error de validacion de hash para el archivo " << encriptadoFileName << std::endl;
            errores_verificacion = true;
        }

        if (!errores_verificacion && !compararArchivos(originalFileName, desencriptadoFileName)) {
            std::cout << "Error: El archivo desencriptado " << desencriptadoFileName << " no coincide con el original." << std::endl;
            errores_verificacion = true;
        }

        auto end_file_process = std::chrono::high_resolution_clock::now();
        auto duration_file = std::chrono::duration_cast<std::chrono::microseconds>(end_file_process - start_file_process);
        tiempos_por_archivo.push_back(duration_file.count());
        std::cout << "Tiempo " << std::setw(2) << std::setfill('0') << i << " : " << formatDuration(duration_file.count()) << std::endl;

        // Solo eliminar archivos temporales, mantener los desencriptados para debug
        remove(copiaFileName.c_str());
        remove(encriptadoFileName.c_str());
        remove(hashFileName.c_str());
        // NO eliminar desencriptadoFileName para poder revisarlo
    }

    auto tfin_total_chrono = std::chrono::high_resolution_clock::now();
    auto tt_total = std::chrono::duration_cast<std::chrono::microseconds>(tfin_total_chrono - ti_total_chrono);

    long long sum_tiempos = 0;
    for (long long t : tiempos_por_archivo) {
        sum_tiempos += t;
    }
    long long tppa_microseconds = (N > 0) ? (sum_tiempos / N) : 0;

    std::cout << "TFIN : " << formatDuration(tt_total.count()) << std::endl;
    std::cout << "TPPA : " << formatDuration(tppa_microseconds) << std::endl;
    std::cout << "TT: " << formatDuration(tt_total.count()) << std::endl;

    if (errores_verificacion) {
        std::cout << "Hubo errores en la verificacion final." << std::endl;
    } else {
        std::cout << "No se encontraron errores en la verificacion final." << std::endl;
    }
    
    std::cout << "---------------------------------------------------------------" << std::endl;

    return tt_total.count();
}

// La implementación de ejecutarProcesoOptimizado será similar,
// pero aquí es donde aplicarás tus estrategias de optimización.
// Por ejemplo, podrías usar hilos (std::thread) para paralelizar el procesamiento de archivos.
// Para usar std::thread, necesitarás #include <thread> y quizás un mutex si compartes recursos.
void ejecutarProcesoOptimizado(int N, const std::string& originalFileName, long long tiempoBase) {
    auto ti_total_chrono = std::chrono::high_resolution_clock::now();
    
    std::cout << "---------------------------------------------------------------" << std::endl;
    std::cout << "PROCESO OPTIMIZADO" << std::endl;
    std::cout.flush();
    std::cout << "TI: " << formatDuration(0) << std::endl;

    std::vector<long long> tiempos_por_archivo(N, 0);
    bool errores_verificacion = false;
    std::mutex mtx;

    // Optimización: Determinar número de threads óptimo
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    
    // Optimización: Limitar threads para evitar overhead
    if (num_threads > 8) num_threads = 8;
    
    std::cout << "Usando " << num_threads << " threads para optimizacion" << std::endl;

    // Optimización: Usar std::async para mejor gestión de threads
    std::vector<std::future<void>> futures;
    
    // Lanzar todos los trabajos en paralelo
    for (int i = 1; i <= N; ++i) {
        futures.emplace_back(std::async(std::launch::async, procesarArchivo, i, 
                                       std::ref(originalFileName), std::ref(tiempos_por_archivo), 
                                       std::ref(mtx), std::ref(errores_verificacion)));
    }
    
    // Esperar a que todos terminen
    for (auto& future : futures) {
        future.wait();
    }

    auto tfin_total_chrono = std::chrono::high_resolution_clock::now();
    auto tt_total = std::chrono::duration_cast<std::chrono::microseconds>(tfin_total_chrono - ti_total_chrono);

    long long sum_tiempos = 0;
    for (long long t : tiempos_por_archivo) {
        sum_tiempos += t;
    }
    long long tppa_microseconds = (N > 0) ? (sum_tiempos / N) : 0;

    std::cout << "TFIN : " << formatDuration(tt_total.count()) << std::endl;
    std::cout << "TPPA : " << formatDuration(tppa_microseconds) << std::endl;
    std::cout << "TT: " << formatDuration(tt_total.count()) << std::endl;

    if (errores_verificacion) {
        std::cout << "Hubo errores en la verificacion final." << std::endl;
    } else {
        std::cout << "No se encontraron errores en la verificacion final." << std::endl;
    }

    // Calcula DF y PM usando el tiempo base pasado como parámetro
    long long df_microseconds = tiempoBase - tt_total.count();
    double pm_porcentaje = (static_cast<double>(df_microseconds) / tiempoBase) * 100.0;

    std::cout << "DF: " << formatDuration(df_microseconds) << std::endl;
    std::cout << "PM: " << std::fixed << std::setprecision(2) << pm_porcentaje << " %" << std::endl;
    std::cout << "---------------------------------------------------------------" << std::endl;
}

// Función para procesar un archivo individual (para usar en threads)
void procesarArchivo(int i, const std::string& originalFileName, std::vector<long long>& tiempos_por_archivo, std::mutex& mtx, bool& errores_verificacion) {
    auto start_file_process = std::chrono::high_resolution_clock::now();

    std::string copiaFileName = std::to_string(i) + ".txt";
    std::string encriptadoFileName = std::to_string(i) + ".enc";
    std::string hashFileName = std::to_string(i) + ".sha";
    std::string desencriptadoFileName = std::to_string(i) + "2.txt";

    // Procesar archivo individual
    copiarArchivo(originalFileName, copiaFileName);
    encriptarArchivo(copiaFileName, encriptadoFileName);
    std::string hash_generado = generarHashSHA256(copiaFileName);
    
    std::ofstream hash_ofs(hashFileName);
    if (hash_ofs.is_open()) {
        hash_ofs << hash_generado;
        hash_ofs.close();
    } else {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "Error: No se pudo crear el archivo hash: " << hashFileName << std::endl;
        errores_verificacion = true;
    }

    desencriptarArchivo(encriptadoFileName, desencriptadoFileName);
    std::string hash_leido_para_validacion;
    std::ifstream hash_ifs(hashFileName);
    if (hash_ifs.is_open()) {
        hash_ifs >> hash_leido_para_validacion;
        hash_ifs.close();
    } else {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "Error: No se pudo leer el archivo hash: " << hashFileName << std::endl;
        errores_verificacion = true;
    }

    std::string hash_desencriptado = generarHashSHA256(desencriptadoFileName);
    if (!errores_verificacion && hash_desencriptado != hash_leido_para_validacion) {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "Error de validacion de hash para el archivo " << encriptadoFileName << std::endl;
        errores_verificacion = true;
    }

    if (!errores_verificacion && !compararArchivos(originalFileName, desencriptadoFileName)) {
        std::lock_guard<std::mutex> lock(mtx);
        std::cout << "Error: El archivo desencriptado " << desencriptadoFileName << " no coincide con el original." << std::endl;
        errores_verificacion = true;
    }

    auto end_file_process = std::chrono::high_resolution_clock::now();
    auto duration_file = std::chrono::duration_cast<std::chrono::microseconds>(end_file_process - start_file_process);
    
    // Guardar tiempo de forma thread-safe
    {
        std::lock_guard<std::mutex> lock(mtx);
        tiempos_por_archivo[i-1] = duration_file.count();
        std::cout << "Tiempo " << std::setw(2) << std::setfill('0') << i << " : " << formatDuration(duration_file.count()) << std::endl;
    }

    // Limpiar archivos temporales
    remove(copiaFileName.c_str());
    remove(encriptadoFileName.c_str());
    remove(hashFileName.c_str());
    // NO eliminar desencriptadoFileName para poder revisarlo
}

// Función para optimizar la configuración de Windows
void optimizarConfiguracionWindows() {
    // Establecer prioridad alta para el proceso actual
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    
    // Configurar threads para usar todos los núcleos disponibles
    SetProcessAffinityMask(GetCurrentProcess(), 0xFFFFFFFF);
}
