echo "ACE Hash..."

# for file in ./../../../data_file_set/*; do 
#     if [ -f "$file" ]; then 
#         ./acehashbenchmark "$file"
#     fi 
# done

./acehashbenchmark  ../../../data_file_set/4kb.txt
./acehashbenchmark  ../../../data_file_set/8kb.txt
./acehashbenchmark  ../../../data_file_set/16kb.txt
./acehashbenchmark  ../../../data_file_set/32kb.txt
./acehashbenchmark  ../../../data_file_set/64kb.txt
./acehashbenchmark  ../../../data_file_set/128kb.txt
./acehashbenchmark  ../../../data_file_set/256kb.txt
./acehashbenchmark  ../../../data_file_set/512kb.txt
./acehashbenchmark  ../../../data_file_set/1mb.txt
./acehashbenchmark  ../../../data_file_set/4mb.txt
./acehashbenchmark  ../../../data_file_set/8mb.txt
./acehashbenchmark  ../../../data_file_set/16mb.txt
./acehashbenchmark  ../../../data_file_set/32mb.txt
./acehashbenchmark  ../../../data_file_set/64mb.txt

rm ../../../data_file_set/*.hash

echo "Done."
