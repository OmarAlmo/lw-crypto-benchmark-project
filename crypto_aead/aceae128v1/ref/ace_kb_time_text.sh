echo "ACE encryption..."

# for file in ./../../../../kb_data/*; do
#     if [ -f "$file" ]; then
#         ./ace128 "$file"
#     fi
# done

./ace128  ../../../data_file_set/4kb.txt
./ace128  ../../../data_file_set/8kb.txt
./ace128  ../../../data_file_set/16kb.txt
./ace128  ../../../data_file_set/32kb.txt
./ace128  ../../../data_file_set/64kb.txt
./ace128  ../../../data_file_set/128kb.txt
./ace128  ../../../data_file_set/256kb.txt
./ace128  ../../../data_file_set/512kb.txt
./ace128  ../../../data_file_set/1mb.txt
./ace128  ../../../data_file_set/4mb.txt
./ace128  ../../../data_file_set/8mb.txt
./ace128  ../../../data_file_set/16mb.txt
./ace128  ../../../data_file_set/32mb.txt
./ace128  ../../../data_file_set/64mb.txt

echo "Done."
