//
//  test_external_functions_script.c
//  vmir
//
//  Created by Timothy Prepscius on 4/9/16.
//  Copyright (c) 2016 Timothy Prepscius. All rights reserved.
//

#include "test_external_functions_script.h"

void external_print (const char *message);

void script_function ()
{
	external_print("hello");
}