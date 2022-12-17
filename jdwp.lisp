;;; https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-spec.html
;;; https://docs.oracle.com/en/java/javase/17/docs/api/jdk.jdi/module-summary.html
;;; java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8888 clojure.main -e '(while true (Thread/sleep 500))'

(defpackage :jdwp
  (:use :common-lisp))

(in-package :jdwp)

(defconstant +packet-header-length+ 11)

(defvar *packet-id* 0)

;;; Utilities

(defun read-integer (octets &key (offset 0) (size (- (length octets) offset)))
  (loop :with value = 0
	:for i :from 0 :below size
	:do (setf value (+ (ash value 8) (aref octets (+ i offset))))
	:finally (return value)))

(defun write-integer (octets value &key (offset 0) (size (- (length octets) offset)))
  (loop :for i :from 0 :below size
	:do (setf (aref octets (+ i offset)) (ldb (byte 8 (* (- size i 1) 8)) value))
	:finally (return value)))

(defun write-octets (target source &key (offset 0) (size (min (length source) (- (length target) offset))))
  (loop :for i :from 0 :below size
	:do (setf (aref target (+ i offset)) (aref source i))
	:finally (return source)))

(defun value-size (value)
  (case (getf value :type)
    (boolean 2)
    ((class-loader class-object object string thread) 9)))

(defun read-value (data &key (offset 0))
  (let ((type (case (aref data offset)
		(76 'object)
		(90 'boolean)
		(99 'class-object)
		(108 'class-loader)
		(115 'string)
		(116 'thread))))
    (list :type type
	  :value (case type
		   (boolean (aref data (1+ offset)))
		   ((class-loader class-object object string thread)
		    (read-integer data :offset (1+ offset) :size 8))))))

(defun write-value (value data &key (offset 0))
  (setf (aref data offset) (case (getf value :type)
			     (object 76)
			     (boolean 90)
			     (class-object 99)
			     (class-loader 108)
			     (string 115)
			     (thread 116)))
  (case (getf value :type)
    (boolean (setf (aref data (1+ offset)) (if (getf value :value) 1 0)))
    ((class-loader class-object object string thread)
     (write-integer data (getf value :value) :offset (1+ offset) :size 8))))

;;; Communication

(defun connect (address port)
  (let ((handshake "JDWP-Handshake")
	(target (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect target address port)
    (sb-bsd-sockets:socket-send target handshake (length handshake))
    (assert (string= handshake (sb-bsd-sockets:socket-receive target nil (length handshake))))
    target))

(defun receive-packet (target &optional (request-id 0))
  (let* ((header (sb-bsd-sockets:socket-receive target nil +packet-header-length+
						:element-type '(unsigned-byte 8) :waitall t))
	 (length (read-integer header :size 4))
	 (data-length (- length +packet-header-length+))
	 (id (read-integer header :offset 4 :size 4))
	 (flags (aref header 8)))
    (cond ((= flags 0)
	   (let ((command-set (aref header 9))
		 (command (aref header 10)))
	     (list command-set
		   command
		   (when (plusp data-length)
		     (sb-bsd-sockets:socket-receive target nil data-length
						    :element-type '(unsigned-byte 8) :waitall t)))))
	  ((= flags #x80)
	   (let ((error-code (read-integer header :offset 9 :size 2)))
	     (if (plusp error-code)
		 (list :error error-code)
		 (prog1
		     (when (plusp data-length)
		       (sb-bsd-sockets:socket-receive target nil data-length
						      :element-type '(unsigned-byte 8) :waitall t))
		   (assert (= id request-id))))))
	  (t (list :error :unknown)))))

(defun send-packet (target command-set command &optional (data ""))
  (let ((header (make-array +packet-header-length+ :element-type '(unsigned-byte 8)))
	(id (incf *packet-id*))
	(length (+ +packet-header-length+ (length data))))
    ;; length
    (write-integer header length :size 4)
    ;; id
    (write-integer header id :offset 4 :size 4)
    ;; flags
    (setf (aref header 8) 0)
    ;; command set
    (setf (aref header 9) command-set)
    ;; command
    (setf (aref header 10) command)

    (sb-bsd-sockets:socket-send target header nil)
    (sb-bsd-sockets:socket-send target data nil)

    id))

;;; VirtualMachine Command Set (1)

(defun virtual-machine/version (target)
  (let ((response (receive-packet target (send-packet target 1 1))))
    (let* ((description-size (read-integer response :size 4))
	   (vm-version-size (read-integer response :offset (+ 12 description-size) :size 4))
	   (vm-name-size (read-integer response :offset (+ 16 description-size vm-version-size) :size 4)))
      (list :description (sb-ext:octets-to-string response :start 4 :end (+ 4 description-size))
	    :jdwp-major (read-integer response :offset (+ 4 description-size) :size 4)
	    :jdwp-minor (read-integer response :offset (+ 8 description-size) :size 4)
	    :vm-version (sb-ext:octets-to-string response :start (+ 16 description-size)
							  :end (+ 16 description-size vm-version-size))
	    :vm-name (sb-ext:octets-to-string response :start (+ 20 description-size vm-version-size)
						       :end (+ 20 description-size vm-version-size vm-name-size))))))

(defun virtual-machine/class-by-signature (target signature)
  (let* ((octets (sb-ext:string-to-octets signature))
	 (length (length octets))
	 (data (make-array (+ 4 length) :element-type '(unsigned-byte 8))))
    (write-integer data length :size 4)
    (write-octets data octets :offset 4)
    (let ((response (receive-packet target (send-packet target 1 2 data))))
      (loop :with offset = 4
	    :repeat (read-integer response :size 4)
	    :collect (list :ref-type-tag (aref response offset)
			   :type-id (read-integer response :offset (1+ offset) :size 8)
			   :status (read-integer response :offset (+ offset 9) :size 4))
	    :do (incf offset 13)))))

(defun virtual-machine/all-classes (target)
  (let ((response (receive-packet target (send-packet target 1 3))))
    (loop :with offset = 4
	  :repeat (read-integer response :size 4)
	  :for signature-size = (read-integer response :offset (+ offset 9) :size 4)
	  :collect (list :ref-type-tag (aref response offset)
			 :type-id (read-integer response :offset (1+ offset) :size 8)
			 :signature (sb-ext:octets-to-string response
							     :start (+ offset 13)
							     :end (+ offset 13 signature-size))
			 :status (read-integer response :offset (+ offset 13 signature-size) :size 4))
	  :do (incf offset (+ 17 signature-size)))))

(defun virtual-machine/all-threads (target)
  (let ((response (receive-packet target (send-packet target 1 4))))
    (loop :with offset = 4
	  :repeat (read-integer response :size 4)
	  :collect (read-integer response :offset offset :size 8)
	  :do (incf offset 8))))

(defun virtual-machine/top-level-thread-groups (target)
  (let ((response (receive-packet target (send-packet target 1 5))))
    (loop :with offset = 4
	  :repeat (read-integer response :size 4)
	  :collect (read-integer response :offset offset :size 8)
	  :do (incf offset 8))))

(defun virtual-machine/dispose (target)
  (receive-packet target (send-packet target 1 6)))

(defun virtual-machine/id-sizes (target)
  (let ((response (receive-packet target (send-packet target 1 7))))
    (list :field-id-size (read-integer response :size 4)
	  :method-id-size (read-integer response :offset 4 :size 4)
	  :object-id-size (read-integer response :offset 8 :size 4)
	  :reference-type-id-size (read-integer response :offset 12 :size 4)
	  :frame-id-size (read-integer response :offset 16))))

(defun virtual-machine/suspend (target)
  (receive-packet target (send-packet target 1 8)))

(defun virtual-machine/resume (target)
  (receive-packet target (send-packet target 1 9)))

(defun virtual-machine/exit (target exit-code)
    (let ((data (make-array 4 :element-type '(unsigned-byte 8))))
    (write-integer data exit-code)
    (receive-packet target (send-packet target 1 10 data))))

(defun virtual-machine/create-string (target utf)
  (let* ((octets (sb-ext:string-to-octets utf))
	 (length (length octets))
	 (data (make-array (+ 4 length) :element-type '(unsigned-byte 8))))
    (write-integer data length :size 4)
    (write-octets data octets :offset 4)
    (read-integer (receive-packet target (send-packet target 1 11 data)))))

;;; ReferenceType Command Set (2)

(defun reference-type/signature (target ref-type)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data ref-type)
    (let ((response (receive-packet target (send-packet target 2 1 data))))
      (sb-ext:octets-to-string response :start 4 :end (+ 4 (read-integer response :size 4))))))

(defun reference-type/class-loader (target ref-type)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data ref-type :size 8)
    (let ((response (receive-packet target (send-packet target 2 2 data))))
      (read-integer response :size 8))))

(defun reference-type/methods (target ref-type)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data ref-type :size 8)
    (let ((response (receive-packet target (send-packet target 2 5 data))))
      (loop :with offset = 4
	    :repeat (read-integer response :size 4)
	    :for name-size = (read-integer response :offset (+ offset 8) :size 4)
	    :for signature-size = (read-integer response :offset (+ offset 12 name-size) :size 4)
	    :collect (list :method-id (read-integer response :offset offset :size 8)
			   :name (sb-ext:octets-to-string response
							  :start (+ offset 12)
							  :end (+ offset 12 name-size))
			   :signature (sb-ext:octets-to-string response
							       :start (+ offset 16 name-size)
							       :end (+ offset 16 name-size signature-size))
			   :mod-bits (read-integer response
						   :offset (+ offset 16 name-size signature-size)
						   :size 4))
	    :do (incf offset (+ 20 name-size signature-size))))))

;;; ClassType Command Set (3)

(defun class-type/superclass (target clazz)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data clazz :size 8)
    (read-integer (receive-packet target (send-packet target 3 1 data)))))

(defun class-type/invoke-method (target clazz thread method-id &optional (arguments ()) (options 0))
  (let* ((argument-size (loop :for value :in arguments :sum (value-size value)))
	 (data (make-array (+ 32 argument-size) :element-type '(unsigned-byte 8))))
    (write-integer data clazz :size 8)
    (write-integer data thread :offset 8 :size 8)
    (write-integer data method-id :offset 16 :size 8)
    (write-integer data (length arguments) :offset 24 :size 4)
    (loop :with offset = 28
	  :for value :in arguments
	  :do (progn (write-value value data :offset offset) (incf offset (value-size value))))
    (write-integer data options :offset (+ 28 argument-size) :size 4)
    (let* ((response (receive-packet target (send-packet target 3 3 data)))
	   (return-value (read-value response)))
      (list :return-value return-value
	    :exception (read-value response :offset (value-size return-value))))))

(defun class-type/new-instance (target clazz thread method-id &optional (arguments ()) (options 0))
  (let* ((argument-size (loop :for value :in arguments :sum (value-size value)))
	 (data (make-array (+ 32 argument-size) :element-type '(unsigned-byte 8))))
    (write-integer data clazz :size 8)
    (write-integer data thread :offset 8 :size 8)
    (write-integer data method-id :offset 16 :size 8)
    (write-integer data (length arguments) :offset 24 :size 4)
    (loop :with offset = 28
	  :for value :in arguments
	  :do (progn (write-value value data :offset offset) (incf offset (value-size value))))
    (write-integer data options :offset (+ 28 argument-size) :size 4)
    (let* ((response (receive-packet target (send-packet target 3 3 data)))
	   (return-value (read-value response)))
      (list :new-object return-value 
	    :exception (read-value response :offset (value-size return-value))))))

;;; ObjectReference Command Set (9)

(defun object-reference/reference-type (target object)
  (let* ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data object :size 8)
    (let ((response (receive-packet target (send-packet target 9 1 data))))
      (list :ref-type-tag (aref response 0)
	    :type-id (read-integer response :offset 1 :size 8)))))

(defun object-reference/invoke-method
    (target object thread clazz method-id &optional (arguments ()) (options 0))
  (let* ((argument-size (loop :for value :in arguments :sum (value-size value)))
	 (data (make-array (+ 40 argument-size) :element-type '(unsigned-byte 8))))
    (write-integer data object :size 8)
    (write-integer data thread :offset 8 :size 8)
    (write-integer data clazz :offset 16 :size 8)
    (write-integer data method-id :offset 24 :size 8)
    (write-integer data (length arguments) :offset 32 :size 4)
    (loop :with offset = 36
	  :for value :in arguments
	  :do (progn (write-value value data :offset offset) (incf offset (value-size value))))
    (write-integer data options :offset (+ 36 argument-size) :size 4)
    (let* ((response (receive-packet target (send-packet target 9 6 data)))
	   (return-value (read-value response)))
      (list :return-value return-value
	    :exception (read-value response :offset (value-size return-value))))))

;;; StringReference Command Set (10)

(defun string-reference/value (target string-object)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data string-object :size 8)
    (let ((response (receive-packet target (send-packet target 10 1 data))))
      (sb-ext:octets-to-string response :start 4 :end (+ 4 (read-integer response :size 4))))))

;;; ThreadReference Command Set (11)

(defun thread-reference/name (target thread)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data thread :size 8)
    (let ((response (receive-packet target (send-packet target 11 1 data))))
      (sb-ext:octets-to-string response :start 4 :end (+ 4 (read-integer response :size 4))))))

(defun thread-reference/suspend (target thread)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data thread :size 8)
    (receive-packet target (send-packet target 11 2 data))))

(defun thread-reference/resume (target thread)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data thread :size 8)
    (receive-packet target (send-packet target 11 3 data))))

(defun thread-reference/status (target thread)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data thread :size 8)
    (let ((response (receive-packet target (send-packet target 11 4 data))))
      (list :thread-status (read-integer response :size 4)
	    :suspend-status (read-integer response :offset 4 :size 4)))))

;;; ClassLoaderReference Command Set (14)

(defun class-loader-reference/visible-classes (target class-loader-object)
  (let ((data (make-array 8 :element-type '(unsigned-byte 8))))
    (write-integer data class-loader-object :size 8)
    (let ((response (receive-packet target (send-packet target 14 1 data))))
      (loop :with offset = 4
	    :repeat (read-integer response :size 4)
	    :collect (list (aref response offset)
			   (read-integer response :offset (1+ offset) :size 8))
	    :do (incf offset 9)))))

;;; EventRequest Command Set (15)

(defun event-request/set (target event-kind suspend-policy &optional (modifiers ()))
  (let ((data (make-array 6 :element-type '(unsigned-byte 8))))
    (setf (aref data 0) (case event-kind
			  (thread-start 6)
			  (method-entry 40)
			  (otherwise 0)))
    (setf (aref data 1) (case suspend-policy
			  (none 0)
			  (event-thread 1)
			  (all 2)
			  (otherwise 0)))
    (write-integer data (length modifiers) :offset 2 :size 4)
    (read-integer (receive-packet target (send-packet target 15 1 data)))))

(defun event-request/clear (target event-kind request-id)
  (let ((data (make-array 6 :element-type '(unsigned-byte 8))))
    (setf (aref data 0) (case event-kind
			  (thread-start 6)
			  (method-entry 40)
			  (otherwise 0)))
    (write-integer data request-id :offset 1 :size 4)
    (receive-packet target (send-packet target 15 2 data))))

;;; Testing

#|

(progn
  (defparameter *target* (connect #(127 0 0 1) 8888))
  (let ((request-id (event-request/set *target* 'method-entry 'all)))
    (receive-packet *target*)
    (event-request/clear *target* 'method-entry request-id)))

(clojure *target* "clojure.core" "load-string" "(println (namespace \"user\"))")

(string-reference/value *target* (getf (getf (clojure *target* "clojure.core" "load-string"
         "(print-str (conj (map (fn [name]
                                   (cons name
                                         (nth (read-string (clojure.repl/source-fn name)) 3)))
                                (sort (keys (ns-publics 'user))))
                           :usage))")
:return-value) :value))

(clojure *target* "clojure.core" "load-file" "foo.clj")

(clojure *target* "user" "foo")

(clojure *target* "clojure.core" "load" "foo")

(clojure *target* "clojure.core" "println" "Hello, world!")

(virtual-machine/all-threads *target*)

(load-class *target* "clojure.java.api.Clojure")

(virtual-machine/class-by-signature *target* "Ljava/lang/ClassLoader;")

(sb-bsd-sockets:socket-close *target*)

(virtual-machine/exit *target* 0)

|#

;;; Using `Class.forName(name, initialize, loader)` to load classes,
;;; `ClassLoader.loadClass` does not work, as loaded classes should be
;;; initialized.
(defun load-class (target class-name)
  (let* ((class-loader-class
	   (getf (first (virtual-machine/class-by-signature target
							    "Ljava/lang/ClassLoader;"))
		 :type-id))
	 (get-system-class-loader-method
	   (getf (find-if (lambda (meta)
			    (string= (getf meta :name) "getSystemClassLoader"))
			  (reference-type/methods target class-loader-class))
		 :method-id))
	 (thread
	   (find-if (lambda (id)
		      (string= (thread-reference/name target id) "main"))
		    (virtual-machine/all-threads target)))
	 (class-loader-object
	   (getf (getf (class-type/invoke-method target
						 class-loader-class
						 thread
						 get-system-class-loader-method)
		       :return-value)
		 :value))
	 (class-class
	   (getf (first (virtual-machine/class-by-signature target
							    "Ljava/lang/Class;"))
		 :type-id))
	 (for-name-method
	   (getf (find-if (lambda (meta)
			    (and (string= (getf meta :name) "forName")
				 (search ";ZL" (getf meta :signature))
				 (not (search ";L" (getf meta :signature)))))
			  (reference-type/methods target class-class))
		 :method-id)))
    (class-type/invoke-method target
			      class-class
			      thread
			      for-name-method
			      (list (list :type 'string
					  :value (virtual-machine/create-string target class-name))
				    (list :type 'boolean :value 1)
				    (list :type 'object :value class-loader-object)))))

(defun clojure (target namespace function &rest arguments)
  (let* ((class
	   (getf (getf (load-class target "clojure.java.api.Clojure") :return-value) :value))
	 (fn-interface
	   (getf (first (virtual-machine/class-by-signature target
							    "Lclojure/lang/IFn;"))
		 :type-id))
	 (var-method
	   (getf (find-if (lambda (meta)
			    (and (string= (getf meta :name) "var")
				 (search ";L" (getf meta :signature))))
			  (reference-type/methods target class))
		 :method-id))
	 (fn-invoke-method
	   (getf (find-if (lambda (meta)
			    (and (string= (getf meta :name) "invoke")
				 (= (1+ (length arguments)) (count #\; (getf meta :signature)))))
			  (reference-type/methods target fn-interface))
		 :method-id))
	 (thread
	   (find-if (lambda (id)
		      (string= (thread-reference/name target id) "main"))
		    (virtual-machine/all-threads target)))
	 (fn-object
	   (getf (getf (class-type/invoke-method
			target
			class
			thread
			var-method
			(list (list :type 'string
				    :value (virtual-machine/create-string target namespace))
			      (list :type 'string
				    :value (virtual-machine/create-string target function))))
		       :return-value)
		 :value)))
    (object-reference/invoke-method target
				    fn-object
				    thread
				    fn-interface
				    fn-invoke-method
				    (mapcar (lambda (argument)
					      (list :type 'string
						    :value (virtual-machine/create-string target
											  argument)))
					    arguments))))
