#include <stdio.h>
#include <string.h>

/* we use only the first of accepted languages, it should be enough, 
 * shoud'nt it?
**/
static int extract_accepted_languages(const char *headerline)
{
  int cnt = 0;
  char *langarr[10] = { 0 };

  if (headerline == NULL || *headerline == '\0') {
    /* do nothing */
  } else {
    int len = strlen(headerline);
    char *copy = strdup(headerline);
    char *tmp = copy;

    if (!len)
      goto finish;
    cnt++;

    while (cnt < 10) {
      switch (*tmp) {
      case ',':
      case '\0':
	/* strip leading spaces */
	while (*copy == ' ')
	  copy++;
	langarr[cnt - 1] = copy;
	if (!*tmp)
	  goto finish;
	++cnt;
	*tmp++ = '\0';
	copy = tmp;
	break;
      default:
	;
      }
      ++tmp;
    }
  }
finish:
  langarr[cnt] = NULL;
  printf("found %d languages\n", cnt);
  cnt = 0;
  while (langarr[cnt]) {
    printf("  %d: '%s'\n", cnt, langarr[cnt]);
    cnt++;
  }
  return cnt;
}

int main()
{
  extract_accepted_languages("da, de, du, di, da");
  extract_accepted_languages("da, en-gb;q=0.8, en;q=0.7");
  extract_accepted_languages("en-gb;q=0.8, en;q=0.7");
  extract_accepted_languages("da, en-gb;q=0.8");
  extract_accepted_languages("da");
  extract_accepted_languages("");
  return 0;
}
