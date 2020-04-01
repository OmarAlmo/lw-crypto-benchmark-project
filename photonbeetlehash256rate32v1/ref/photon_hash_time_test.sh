echo "Photon-Beetle Hash..."

# for file in ./../../../data_file_set/*; do 
#     if [ -f "$file" ]; then 
#         ./photonhashbenchmark  "$file"
#     fi 
# done

./photonhashbenchmark  ../../data_file_set/4kb.txt
./photonhashbenchmark  ../../data_file_set/8kb.txt
./photonhashbenchmark  ../../data_file_set/16kb.txt
./photonhashbenchmark  ../../data_file_set/32kb.txt
./photonhashbenchmark  ../../data_file_set/64kb.txt
./photonhashbenchmark  ../../data_file_set/128kb.txt
./photonhashbenchmark  ../../data_file_set/256kb.txt
./photonhashbenchmark  ../../data_file_set/512kb.txt
./photonhashbenchmark  ../../data_file_set/1mb.txt
./photonhashbenchmark  ../../data_file_set/4mb.txt
./photonhashbenchmark  ../../data_file_set/8mb.txt
./photonhashbenchmark  ../../data_file_set/16mb.txt
./photonhashbenchmark  ../../data_file_set/32mb.txt
./photonhashbenchmark  ../../data_file_set/64mb.txt

rm ../../../data_file_set/*.hash

echo "Done."
