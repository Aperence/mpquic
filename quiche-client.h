//
//  quiche-client.h
//  quiche-test
//
//  Created by Anthony Doeraene on 05/09/2024.
//

#ifndef quiche_client_h
#define quiche_client_h

#include <stdio.h>
#include <stdint.h>

typedef struct http_response {
    int status;  // 0 or -1
    uint8_t *data;  // the response
    ssize_t len;
} http_response_t;

http_response_t *quiche_fetch(const char *host, const char *port, const char *path);

#endif /* quiche_client_h */
