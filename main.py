import memory

if __name__ == "__main__":
    process_name = "explorer.exe"
    mem = memory.Memory(process_name)
    process_base = mem.get_process_base(process_name)
    print("Process Base: 0x{:X}".format(process_base))