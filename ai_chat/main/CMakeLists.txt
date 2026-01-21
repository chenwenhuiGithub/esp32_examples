idf_component_register(SRCS "main.c" "ir.c" "sr.c" "oled.c"
                       INCLUDE_DIRS "")

# Add voice_data partition and flash esp_tts_voice_data_xxx.dat
if(CONFIG_PARTITION_TABLE_CUSTOM)
    partition_table_get_partition_info(size "--partition-name voice_data" "size")
    partition_table_get_partition_info(offset "--partition-name voice_data" "offset")

    if("${size}" AND "${offset}")
        idf_component_get_property(esp-sr_path espressif__esp-sr COMPONENT_DIR)
        set(voice_data_image ${esp-sr_path}/esp-tts/esp_tts_chinese/esp_tts_voice_data_xiaoxin.dat)
        add_custom_target(voice_data ALL DEPENDS ${voice_data_image})
        add_dependencies(flash voice_data)

        esptool_py_flash_to_partition(flash "voice_data" "${voice_data_image}")
    else()
        set(message "Failed to find voice_data in partition table file"
                    "Please add a line(Name=voice_data, Type=data, Size=3890K) to the partition file.")
    endif()
endif()
