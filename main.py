import pandas as pd
import requests
import time
import os
import re
from datetime import datetime
import json

def read_ips_from_txt(file_path):
    """
    Читает IP-адреса из текстового файла
    """
    ips = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                # Проверяем, что строка похожа на IP-адрес
                if line and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips.append(line)
                elif line:
                    print(f"⚠️ Пропущена строка (не IP-адрес): {line}")
        
        print(f"📖 Прочитано IP-адресов из файла: {len(ips)}")
        return ips
        
    except Exception as e:
        print(f"❌ Ошибка при чтении файла {file_path}: {e}")
        return []

def get_whois_via_api_primary(ip_address):
    """
    Основной метод через API с приоритетом
    """
    apis = [
        # Основные API
        {
            'url': f"http://ipapi.co/{ip_address}/json/",
            'fields': {
                'org': 'org',
                'country': 'country_name',
                'city': 'city',
                'region': 'region',
                'asn': 'asn',
                'isp': 'isp',
                'postal': 'postal',
                'timezone': 'timezone'
            }
        },
        {
            'url': f"http://ipwhois.app/json/{ip_address}",
            'fields': {
                'org': 'org',
                'country': 'country',
                'city': 'city',
                'region': 'region',
                'asn': 'asn',
                'isp': 'isp',
                'postal': 'postal',
                'timezone': 'timezone'
            }
        }
    ]
    
    for api in apis:
        try:
            response = requests.get(api['url'], timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Проверяем, что данные валидны
                if data and not data.get('error') and not data.get('reserved'):
                    result = {}
                    for our_key, api_key in api['fields'].items():
                        result[our_key] = data.get(api_key, 'N/A')
                    
                    # Дополнительная информация
                    result['ip'] = ip_address
                    result['source_api'] = api['url'].split('/')[2]  # Доменное имя API
                    
                    print(f"    ✓ Данные получены от {result['source_api']}")
                    return result
                    
        except Exception as e:
            continue
    
    return None

def extract_network_info(org, asn, isp):
    """
    Извлекает сетевую информацию из доступных данных
    """
    netname = 'N/A'
    asn_description = 'N/A'
    
    # Пытаемся создать осмысленные netname и описания
    if org and org != 'N/A':
        # Создаем netname из названия организации
        netname = re.sub(r'[^a-zA-Z0-9]', '', org.upper())[:20]
        asn_description = org
    
    elif isp and isp != 'N/A':
        netname = re.sub(r'[^a-zA-Z0-9]', '', isp.upper())[:20]
        asn_description = isp
    
    elif asn and asn != 'N/A':
        netname = f"AS{asn}"
        asn_description = f"AS{asn}"
    
    return netname, asn_description

def get_comprehensive_whois_info(ip_address):
    """
    Основная функция получения WHOIS информации
    """
    print(f"  📡 Запрос данных для {ip_address}...")
    
    # Метод 1: Основные API
    api_data = get_whois_via_api_primary(ip_address)
    
    # Если основные API не сработали
    if not api_data:
        print(f"  🔄 Основные API не ответили")
        api_data = {
            'ip': ip_address,
            'org': 'N/A',
            'country': 'N/A',
            'city': 'N/A',
            'region': 'N/A',
            'asn': 'N/A',
            'isp': 'N/A',
            'source_api': 'no_data'
        }
    
    # Извлекаем сетевую информацию
    netname, asn_description = extract_network_info(
        api_data.get('org', 'N/A'),
        api_data.get('asn', 'N/A'),
        api_data.get('isp', 'N/A')
    )
    
    # Формируем полный результат
    result = {
        'ip': ip_address,
        
        # Основная информация
        'organization': api_data.get('org', 'N/A'),
        'country': api_data.get('country', 'N/A'),
        'city': api_data.get('city', 'N/A'),
        'region': api_data.get('region', 'N/A'),
        
        # Сетевая информация
        'netname': netname,
        'asn': api_data.get('asn', 'N/A'),
        'asn_description': asn_description,
        'isp': api_data.get('isp', 'N/A'),
        
        # Дополнительная информация
        'postal_code': api_data.get('postal', 'N/A'),
        'timezone': api_data.get('timezone', 'N/A'),
        
        # Метод получения
        'data_source': api_data.get('source_api', 'multiple_apis'),
        'success': 'Yes' if api_data and api_data.get('org') != 'N/A' else 'No'
    }
    
    # Очистка данных
    for key in result:
        if isinstance(result[key], str):
            result[key] = re.sub(r'\s+', ' ', result[key]).strip()
            if result[key] in ['', 'None', 'null']:
                result[key] = 'N/A'
    
    return result

def save_to_single_excel(whois_results, output_path):
    """
    Сохраняет все данные в один Excel файл с несколькими вкладками
    """
    try:
        # Создаем основной DataFrame
        main_df = pd.DataFrame(whois_results)
        
        # Создаем Excel writer объект
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            
            # 📊 ВКЛАДКА 1: Все результаты
            main_df.to_excel(writer, sheet_name='Все IP-адреса', index=False)
            worksheet_main = writer.sheets['Все IP-адреса']
            
            # Настраиваем ширину колонок для основной вкладки
            column_widths_main = {
                'A': 15,  # IP
                'B': 35,  # Organization
                'C': 15,  # Country
                'D': 15,  # City
                'E': 15,  # Region
                'F': 20,  # Netname
                'G': 10,  # ASN
                'H': 35,  # ASN Description
                'I': 25,  # ISP
                'J': 12,  # Postal Code
                'K': 15,  # Timezone
                'L': 15,  # Data Source
                'M': 10   # Success
            }
            
            for col, width in column_widths_main.items():
                worksheet_main.column_dimensions[col].width = width
            
            # Добавляем фильтры
            worksheet_main.auto_filter.ref = worksheet_main.dimensions
            
            # 📈 ВКЛАДКА 2: Статистика по организациям
            if len(main_df) > 0:
                org_stats = main_df[main_df['organization'] != 'N/A'].groupby('organization').agg({
                    'ip': 'count',
                    'country': 'first',
                    'asn': 'first'
                }).rename(columns={'ip': 'count_ips'}).sort_values('count_ips', ascending=False)
                
                if not org_stats.empty:
                    org_stats.to_excel(writer, sheet_name='По организациям')
                    worksheet_org = writer.sheets['По организациям']
                    worksheet_org.column_dimensions['A'].width = 35
                    worksheet_org.column_dimensions['B'].width = 10
                    worksheet_org.column_dimensions['C'].width = 15
                    worksheet_org.column_dimensions['D'].width = 10
            
            # 🌍 ВКЛАДКА 3: Статистика по странам
            if len(main_df) > 0:
                country_stats = main_df[main_df['country'] != 'N/A'].groupby('country').agg({
                    'ip': 'count',
                    'organization': lambda x: ', '.join(sorted(set(x)))[:100]
                }).rename(columns={'ip': 'count_ips'}).sort_values('count_ips', ascending=False)
                
                if not country_stats.empty:
                    country_stats.to_excel(writer, sheet_name='По странам')
                    worksheet_country = writer.sheets['По странам']
                    worksheet_country.column_dimensions['A'].width = 20
                    worksheet_country.column_dimensions['B'].width = 10
                    worksheet_country.column_dimensions['C'].width = 40
            
            # 🔢 ВКЛАДКА 4: Статистика по ASN
            if len(main_df) > 0:
                asn_stats = main_df[main_df['asn'] != 'N/A'].groupby('asn').agg({
                    'ip': 'count',
                    'organization': 'first',
                    'country': 'first'
                }).rename(columns={'ip': 'count_ips'}).sort_values('count_ips', ascending=False)
                
                if not asn_stats.empty:
                    asn_stats.to_excel(writer, sheet_name='По ASN')
                    worksheet_asn = writer.sheets['По ASN']
                    worksheet_asn.column_dimensions['A'].width = 15
                    worksheet_asn.column_dimensions['B'].width = 10
                    worksheet_asn.column_dimensions['C'].width = 35
                    worksheet_asn.column_dimensions['D'].width = 15
            
            # ✅ ВКЛАДКА 5: Только успешные результаты
            successful_df = main_df[main_df['success'] == 'Yes']
            if not successful_df.empty:
                successful_df.to_excel(writer, sheet_name='Успешные запросы', index=False)
                worksheet_success = writer.sheets['Успешные запросы']
                
                # Копируем форматирование ширины колонок из основной вкладки
                for col, width in column_widths_main.items():
                    worksheet_success.column_dimensions[col].width = width
                worksheet_success.auto_filter.ref = worksheet_success.dimensions
            
            # 📋 ВКЛАДКА 6: Сводка и статистика
            summary_data = {
                'Метрика': [
                    'Всего обработано IP-адресов',
                    'Успешных запросов',
                    'Процент успешных запросов',
                    'Уникальных организаций',
                    'Уникальных стран',
                    'Уникальных ASN',
                    'Время начала',
                    'Время окончания'
                ],
                'Значение': [
                    len(main_df),
                    len(successful_df),
                    f"{(len(successful_df) / len(main_df) * 100):.1f}%" if len(main_df) > 0 else "0%",
                    main_df['organization'].nunique() if len(main_df) > 0 else 0,
                    main_df['country'].nunique() if len(main_df) > 0 else 0,
                    main_df['asn'].nunique() if len(main_df) > 0 else 0,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'В процессе...'
                ]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Сводка', index=False)
            worksheet_summary = writer.sheets['Сводка']
            worksheet_summary.column_dimensions['A'].width = 30
            worksheet_summary.column_dimensions['B'].width = 25
            
        print(f"✅ Единый Excel файл создан: {output_path}")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при сохранении в Excel: {e}")
        return False

def main():
    # Получаем путь к директории, где находится скрипт
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Имя текстового файла с IP-адресами (в той же папке что и скрипт)
    input_txt_file = "ip_list.txt"
    input_file_path = os.path.join(script_dir, input_txt_file)
    
    # Выходной Excel файл (в той же папке что и скрипт)
    output_excel_file = os.path.join(script_dir, 'WHOIS_Analysis_Report.xlsx')
    
    print("🚀 WHOIS АНАЛИЗАТОР IP-АДРЕСОВ")
    print("=====================================")
    print(f"📂 Рабочая директория: {script_dir}")
    print(f"📄 Входной файл: {input_txt_file}")
    print(f"💾 Выходной файл: WHOIS_Analysis_Report.xlsx")
    print(f"⏰ Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Проверяем существование файла
    if not os.path.exists(input_file_path):
        print(f"❌ Ошибка: файл {input_txt_file} не найден!")
        print("💡 Убедитесь, что файл ip_list.txt находится в той же папке что и скрипт")
        return
    
    # Читаем IP-адреса из текстового файла
    unique_ips = read_ips_from_txt(input_file_path)
    
    if not unique_ips:
        print("❌ Не удалось прочитать IP-адреса из файла")
        return
    
    # Удаляем дубликаты
    unique_ips = list(set(unique_ips))
    print(f"🔍 Уникальных IP-адресов для обработки: {len(unique_ips)}")
    
    # Собираем WHOIS информацию
    whois_results = []
    
    print(f"\n🔄 Начинаем сбор WHOIS информации...")
    print("💡 Используются API: ipapi.co, ipwhois.app")
    
    successful_count = 0
    failed_ips = []
    
    start_time = datetime.now()
    
    for i, ip in enumerate(unique_ips, 1):
        print(f"\n--- [{i}/{len(unique_ips)}] Обрабатываю: {ip} ---")
        
        try:
            # Получаем WHOIS информацию
            result = get_comprehensive_whois_info(ip)
            whois_results.append(result)
            
            # Проверяем успешность
            if result['success'] == 'Yes':
                successful_count += 1
                status = "✅ УСПЕХ"
            else:
                failed_ips.append(ip)
                status = "⚠️ ДАННЫЕ НЕ ПОЛУЧЕНЫ"
            
            # Выводим результаты
            print(f"{status}")
            print(f"🏢 Организация: {result['organization']}")
            print(f"🌍 Страна: {result['country']}")
            print(f"🏙️ Город: {result['city']}")
            print(f"🔢 ASN: {result['asn']}")
            print(f"📡 ISP: {result['isp']}")
            
        except Exception as e:
            print(f"❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
            # Добавляем запись об ошибке
            whois_results.append({
                'ip': ip,
                'organization': f'ERROR: {str(e)[:50]}',
                'country': 'N/A',
                'city': 'N/A',
                'region': 'N/A',
                'netname': 'N/A',
                'asn': 'N/A',
                'asn_description': 'N/A',
                'isp': 'N/A',
                'postal_code': 'N/A',
                'timezone': 'N/A',
                'data_source': 'ERROR',
                'success': 'No'
            })
            failed_ips.append(ip)
        
        # Пауза чтобы не заблокировали
        time.sleep(1.0)
    
    # Сохраняем все результаты в ОДИН Excel файл
    excel_saved = save_to_single_excel(whois_results, output_excel_file)
    
    end_time = datetime.now()
    processing_time = end_time - start_time
    
    print(f"\n{'='*60}")
    print("📊 РЕЗУЛЬТАТЫ АНАЛИЗА")
    print(f"{'='*60}")
    print(f"✅ Обработано IP-адресов: {len(whois_results)}")
    print(f"✅ Успешно получено данных: {successful_count}/{len(whois_results)} ({successful_count/len(whois_results)*100:.1f}%)")
    print(f"⏱️ Время обработки: {processing_time}")
    
    if failed_ips:
        print(f"⚠️ Не удалось получить данные для: {len(failed_ips)} IP")
        if len(failed_ips) <= 10:
            print(f"   Проблемные IP: {', '.join(failed_ips[:10])}")
    
    print(f"⏰ Время окончания: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if excel_saved:
        print(f"💾 Все результаты сохранены в: WHOIS_Analysis_Report.xlsx")

if __name__ == "__main__":
    # Установите если нужно: 
    # pip install requests pandas openpyxl
    
    main()
    
    print(f"\n{'='*60}")
    print("🎉 АНАЛИЗ ЗАВЕРШЕН!")
    print(f"{'='*60}")
    
    print(f"\n💡 Для повторного запуска выполните: py main.py")