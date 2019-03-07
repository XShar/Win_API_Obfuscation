# Win_API_Obfuscation
WinAPIObfuscation - Движок для скрытия вызываемых Win API функций.

Скрытие происходит путем вызова функций по их хеш-значениям.

Изначательно идея была взята со статьи с "Хакера":https://xakep.ru/2018/12/06/hidden-winapi/

Ознакомится с полной версией статьи можно здесь (Также связаться с автором данной работы):https://ru-sfera.org/threads/kak-obfuscirovat-vyzovy-winapi.3743/

Описание модуля:

1)MurmurHash2A.cpp - Реализация хеширования по алгоритму MurmurHash2A (https://ru.wikipedia.org/wiki/MurmurHash2).

2)hash_work.cpp - Реализация функций, которые вызовут скрываемую функцию по её хешу.

3)export_work.cpp - Реализация основных функций движка, а конкретно:
get_api - Которая получает адрес скрываемой функции.

4)WinAPIObfuscation.cpp - Демонстрационный пример, как использовать (Скрывает две функции CreateFile и LoadLibraryA).

Как использовать движок (Добавлять свои функции для скрытия):

1. Добавить в заголовок hash_work.h, прототип скрываемой функции, пример для CreateFile:

HANDLE hash_CreateFileA(
	__in    LPCSTR      file_name,
	__in    DWORD     access,
	__in    DWORD     share_mode,
	__in    LPSECURITY_ATTRIBUTES security,
	__in    DWORD     creation_disposition,
	__in    DWORD     flags,
	__in HANDLE    template_file); 

2. Объявить указатель на скрываемую функцию в файле PointerHashFunc.h, например:

HANDLE(WINAPI *temp_CreateFile)(__in LPCSTR file_name,
	__in DWORD access,
	__in DWORD share,
	__in LPSECURITY_ATTRIBUTES security,
	__in DWORD creation_disposition,
	__in DWORD flags,
	__in HANDLE template_file) = NULL; 

В temp_CreateFile мы получим адрес скрываемой функции, для её запуска.

3. Реализовать нашу функцию hash_CreateFileA в файле hash_work.cpp, пример с описанием:

HANDLE hash_CreateFileA(
	__in    LPCSTR      file_name,
	__in    DWORD     access,
	__in    DWORD     share_mode,
	__in    LPSECURITY_ATTRIBUTES security,
	__in    DWORD     creation_disposition,
	__in    DWORD     flags,
	__in HANDLE    template_file) {

	unsigned int create_file_hash = MurmurHash2A("CreateFile", 10, 10);

	temp_CreateFile = (HANDLE(WINAPI *)(LPCSTR,
		DWORD,
		DWORD,
		LPSECURITY_ATTRIBUTES,
		DWORD,
		DWORD,
		HANDLE))get_api(create_file_hash, "Kernel32.dll", 10, 10);

	return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}

Описание что к чему:

- unsigned int create_file_hash = MurmurHash2A("CreateFile", 10, 10);
Хеширует строку "CreateFile" - Это функция, которую мы хотим скрыть.
Воторой параметр, это длина строки.
Третий параметр, это начальное значение (Что-бы хеши разные были например).
  
- temp_CreateFile = (HANDLE(WINAPI *)(LPCSTR,
		DWORD,
		DWORD,
		LPSECURITY_ATTRIBUTES,
		DWORD,
		DWORD,
		HANDLE))get_api(create_file_hash, "Kernel32.dll", 10, 10);

Получаем адрес скрываемой функции при помощи интерфейсной функции get_api(create_file_hash, "Kernel32.dll", 10, 10).

Описание параметров:
- create_file_hash - Полученный выше хеш.
- "Kernel32.dll" - Модуль, где экспортируется функция.
- Второй параметр, это длина строки (Значение те-же, что и при получении create_file_hash).
- Третий параметр, это начальное значение (Значение те-же, что и при получении create_file_hash).

Далее передаём управление по адресу (С параметрами, как в прототипе):
return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file)

В общем-то и всё.

Пример использования, вызываем:

HANDLE hFile = hash_CreateFileA("log.txt", GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

Как в примере WinAPIObfuscation.cpp (Создаст файл log.txt в папке с программой)

В итоге функция не будет отображаться в отладчике, в импорте.

Функция LoadLibraryA скрыта в движке.
 
