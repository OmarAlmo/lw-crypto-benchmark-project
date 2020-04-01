echo "Saturnin encryption..."

# for file in ./../../../kb_data/*; do
#     if [ -f "$file" ]; then
#         ./saturninbench "$file"
#     fi
# done

./saturninbench  ../../data_file_set/4kb.txt
./saturninbench  ../../data_file_set/8kb.txt
./saturninbench  ../../data_file_set/16kb.txt
./saturninbench  ../../data_file_set/32kb.txt
./saturninbench  ../../data_file_set/64kb.txt
./saturninbench  ../../data_file_set/128kb.txt
./saturninbench  ../../data_file_set/256kb.txt
./saturninbench  ../../data_file_set/512kb.txt
./saturninbench  ../../data_file_set/1mb.txt
./saturninbench  ../../data_file_set/4mb.txt
./saturninbench  ../../data_file_set/8mb.txt
./saturninbench  ../../data_file_set/16mb.txt
./saturninbench  ../../data_file_set/32mb.txt
./saturninbench  ../../data_file_set/64mb.txt

rm *.hash

echo "Done."
