# SAFE_IDA_plugin

This plugin can be used to produce functions embedding using the common disassembler IDA PRO.

## How to Install

Just copy SAFE_plugin.py and word2id.json into IDA PRO plugin folder.

You need to copy also capstone package into the IDA PRO plugin folder. 
To you can install it using pip and then copy the whole package there.

## How to run

You can run it directly from IDA!
You will see the embedding of the current function in the console.
Use the shortcut SHIFT-S to run SAFE faster

## Configuration
To set up the address of the tensorlow serving server, you can go to:
options/SAFE

