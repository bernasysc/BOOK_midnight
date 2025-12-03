from app import app

client = app.test_client()
resp = client.get('/?category=Fiction')
print('STATUS', resp.status_code)
text = resp.get_data(as_text=True)
print('HAS_RESULTS_SECTION:', 'Results' in text or 'More Books' in text)
# print a short excerpt to verify categories/genre buttons presence
start = text.find('<div class="genre-buttons">')
if start!=-1:
    print('FOUND_GENRE_BLOCK')
else:
    print('NO_GENRE_BLOCK')

# print whether any book titles present
import re
titles = re.findall(r'<h3>(.*?)</h3>', text)
print('NUM_TITLES_EXTRACTED:', len(titles))
if len(titles)>0:
    print('SAMPLE_TITLE:', titles[0])
