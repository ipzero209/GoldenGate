#!/usr/bin/python

import shelve



# Get the API from /etc/pan_shim

s_data = shelve.open('./data.db') #TODO - /etc/pan_shim/
api_key = s_data['api_key']
s_data.close()


