// Jenkins hash test bench 
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint32_t jenkins_one_at_a_time_hash(char *key, size_t len) {
    uint32_t hash = 0;
    uint32_t i;
    for(i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}


int main(void) {
  printf("value,len,hash\n");
  char *values[] = {"VOD.L", "hello", "plane", "A", "B", "C", "A", "a", "BT.L", "ARM.L", NULL};
  char **i = values; 
  while (*i) {
    size_t len = strlen(*i);
    printf("%d,%x,%s\n", len, jenkins_one_at_a_time_hash(*i, len), *i);
    i++;
  }
  return 0;
}

