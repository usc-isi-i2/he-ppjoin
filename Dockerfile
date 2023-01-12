FROM openfhe-development

# https://github.com/microsoft/Kuku
RUN git clone https://github.com/microsoft/Kuku.git && cd Kuku && git checkout main && git checkout tags/v2.1.0
RUN cd /Kuku && cmake -S . -B build && cmake --build build && cmake --install build

# https://github.com/efficient/libcuckoo
RUN git clone https://github.com/efficient/libcuckoo.git
RUN mkdir /libcuckoo/build && cd /libcuckoo/build && cmake .. && make all && make install
