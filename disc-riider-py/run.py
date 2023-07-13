import disc_riider_py

extractor = disc_riider_py.WiiIsoExtractor('SOUE01.iso')
extractor.prepare_extract_section('DATA')
# extractor.remove_ss_hint_movies()
# extractor.test_print()
extractor.remove_files_by_callback("DATA", lambda x: x.startswith("THP") and not 'Demo' in x)
extractor.remove_files_by_callback("DATA", lambda x: print(x))
print(extractor.__dir__())
# PAL 1.0 8f6bf468447d9f10172cc4a472a56e1f526a5cb4
# JP      2848bb574bfcbf97f075adc4e0f4692ddd7fd0e8
# US 1.2  30cad7e8a88442b1388867f01bc6461097f4a152
# US 1.0  450a6806f46d59dcf8278db08e06f94865a4b18a
# extractor.add_hash_check("DATA", "/sys/main.dol", bytes.fromhex("450a6806f46d59dcf8278db08e06f94865a4b18a"))
# extractor.extract_to('out-extract', lambda x: print(f"perc: {x}"))
